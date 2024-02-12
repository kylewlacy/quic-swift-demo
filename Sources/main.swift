//
//  main.swift
//  QuicTool
//
//  Created by Andrew Paxson on 2024-01-14.
//

import Foundation
import Network

/// Helper function to create a message frame.
func createMessage(version: UInt8, messageType: UInt8, message: String) -> Data {
    let messageData = message.data(using: .utf8) ?? Data()
    let length = UInt32(messageData.count)

    var data = Data()
    data.append(version)
    data.append(messageType)

    // Convert length to 4 bytes and append (big-endian format)
    let bigEndianLength = length.bigEndian
    data.append(contentsOf: withUnsafeBytes(of: bigEndianLength) { Array($0) })

    // Append 2 bytes of padding for 8-byte alignment
    data.append(Data(repeating: 0, count: 2))

    // Add Message Data.
    data.append(messageData)
    return data
}

// Queue for QUIC things.
let queue = DispatchQueue(label: "quic", qos: .userInteractive)

// Create Inital Options for the tunnel.
// This is using an insecure connection as this operation is meant to be local network.
let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .init(integerLiteral: 4567))
let options =  NWProtocolQUIC.Options(alpn: ["demo"])

// Set the initial stream to bidirectional.
options.direction = .bidirectional

sec_protocol_options_set_verify_block(options.securityProtocolOptions, { (sec_protocol_metadata, sec_trust, sec_protocol_verify_complete) in
    sec_protocol_verify_complete(true)
}, queue)

let parameters = NWParameters(quic: options)

// 1) Create a new multiplexed connection
let descriptor = NWMultiplexGroup(to: endpoint)
let group = NWConnectionGroup(with: descriptor, using: parameters)
var mainConn: NWConnection? = nil

// Here we are establishing a state handler for when the connection to the
// the server is neogiated and "ready". Once its ready we want to establish a
// stream using the group with the options set.
//
// This is the main location of the issue we are seeing where the stream is
// established and the data is sent but never updated.
group.stateUpdateHandler = { newState in
    print("group state: \(newState)")
    switch newState {

    // Once the tunnel is established, create a new stream with bidirectional parameters.
    case .ready:
        print("Connected using QUIC!")

        // 2) In normal application I may want to open different kinds of streams in providing
        // new options. Is there a better way to select the stream kind for subsequent streams?
        // let options =  NWProtocolQUIC.Options(alpn: ["demo"])
        // options.direction = .bidirectional

        // When providing unique options the stream will fail. Removeing the using argument works.
        mainConn = group.extract()! // force unwrap
        guard let mainConn else {
            print("mainConn not set")
            return
        }

        mainConn.stateUpdateHandler = { state in
                print("Main Connection State: \(state)")
            switch state {
            case .ready:
                // Once the connection is ready, lets send some sweet data sauce.
                //
                // By establishing this new stream and sending data, on the server this causes the inital
                // stream with no handle to be open.
                // let version: UInt8 = 1
                // let messageType: UInt8 = 1
                // let message = "hello, I am from the multiplex group ready."
                // let messageData = createMessage(version: version, messageType: messageType, message: message)

                mainConn.send(content: Data(count: 4), isComplete: false, completion: .contentProcessed({ error in
                    if let error {
                        print("Error sending: \(error)")
                    } else {
                        print("Sent")
                    }
                }))

                mainConn.receive(minimumIncompleteLength: 1, maximumLength: 1000) { (content, _, isComplete, error) in
                    if let error {
                        print("Receive error: \(error)")
                        return
                    }
                    if !isComplete {
                        print("Did not get complete message")
                        return
                    }
                    guard let content else {
                        print("No data")
                        return
                    }

                    let contentString = String(decoding: content, as: UTF8.self)
                    print("Received: \(contentString)")

                    mainConn.send(content: .none, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                    let nextConn = group.extract()!
                    nextConn.stateUpdateHandler = {
                        print("new state: \($0)")
                        switch $0 {
                        case .ready:
                            nextConn.send(content: Data(count: 4), contentContext: .finalMessage, isComplete: true, completion: .contentProcessed({_ in
                                print("Connection finished")
                                group.cancel()
                            }))
                        default:
                            break
                        }
                    }
                    nextConn.start(queue: queue)
//                    mainConn.cancel()

//                    mainConn.send(content: .none, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
//                    mainConn.cancel()
                }
//                mainConn.receive(minimumIncompleteLength: 1, maximumLength: 1000) { (content, _, isComplete, error) in
//                    let contentString = String(decoding: content ?? Data(), as: UTF8.self)
//                    if let error {
//                        print("Receive error: \(error)")
//                        return
//                    }
//                    print("Received content: \(contentString), isComplete=\(isComplete)")
//                }

                // mainConn?.send(content: messageData, isComplete: true, completion: .contentProcessed({ sendError in
                //     if let error = sendError {
                //         print("There was an error sending data: \(error)")
                //     } else {
                //         print("Data was sent successfully from Main Connection.")
                //     }
                // }))

            default:
                break
            }
        }
        // Don't forget to start the connection.
        mainConn.start(queue: queue)
    default:
        break
    }
}

// Receive new incoming streams initiated by the remote endpoint
// this is not used for this example.
group.newConnectionHandler = { conn in
    print("New Connection: \(conn)")

  // Set state update handler on incoming stream
    conn.stateUpdateHandler = { newState in
      print("newState: \(newState) for \(conn)")
      switch newState {
      case .ready:
          print("got a new stream!")
      default:
          break
      }
  }
  // Start the incoming stream
    conn.start(queue: queue)
}

// Start the group with callback queue
group.start(queue: queue)

print("running....")
// We iterate trying to send data on the new stream we created after the
// connection is established.
while true {
    switch mainConn?.state {
    case .ready:
        // Once the connection is ready, lets send some sweet data sauce.
//        let version: UInt8 = 1
//        let messageType: UInt8 = 1
//        let message = "hello, im from the main loop"
//        let messageData = createMessage(version: version, messageType: messageType, message: message)
//        print("Local Stream Send: \(messageData)")
        // mainConn?.receive(minimumIncompleteLength: 1, maximumLength: 1000) { (content, _, _, error) in
        //     if let error {
        //         print("Main loop error: \(error)")
        //     }

        //     if let content {
        //         print("received content")
        //     }
        // }

        // mainConn?.send(content: messageData, completion: .contentProcessed({ sendError in
        //     if let error = sendError {
        //         print("There was an error sending data: \(error)")
        //     }
        // }))
        // One thing I tried was to try send data on the group connection, again the ghost stream is opened but has no
        // handle and a new stream is open for each call to send.
//        group.send(content: messageData, completion: { sendError in
//            if let error = sendError {
//                print("There was an error sending data: \(error)")
//            }
//        })

        sleep(1)
    default:
        continue
    }
}

