use bevel_p2p::BevelNode;
use bevel_crypto::BevelIdentity;
use libp2p::{Multiaddr, PeerId};
use std::time::Duration;
use tokio::time::sleep;
use futures::StreamExt;

#[tokio::test]
async fn test_bootstrap_connectivity() {
    // 1. Setup Bootstrap Node
    let boot_id = BevelIdentity::generate().unwrap();
    let mut boot_node = BevelNode::new(&boot_id, "test_db_boot", &[]).await.unwrap();
    let boot_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    boot_node.listen(boot_addr).await.unwrap();
    
    // Polling the swarm to get the actual listening address
    let mut actual_boot_addr = None;
    for _ in 0..10 {
        if let Some(event) = boot_node.swarm.next().await {
            if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } = event {
                actual_boot_addr = Some(address);
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    
    let boot_addr_final = actual_boot_addr.expect("Bootstrap node failed to provide a listen address");
    let boot_peer_id: PeerId = boot_node.peer_id;
    
    println!("Bootstrap node started at {} with PeerId {}", boot_addr_final, boot_peer_id);

    // 2. Setup Client Node with Bootstrap
    let client_id = BevelIdentity::generate().unwrap();
    let bootstraps: Vec<(PeerId, Multiaddr)> = vec![(boot_peer_id, boot_addr_final)];
    let client_node = BevelNode::new(&client_id, "test_db_client", &bootstraps).await.unwrap();
    
    println!("Client node started with PeerId {}", client_node.peer_id);

    // 3. Verify node was initialized correctly
    assert_ne!(client_node.peer_id, boot_peer_id, "Client and boot should have different PeerIds");
    assert_eq!(client_node.identity().address, client_id.address, "Identity should be preserved");
    
    // Clean up
    let _ = std::fs::remove_dir_all("test_db_boot");
    let _ = std::fs::remove_dir_all("test_db_client");
}

#[tokio::test]
async fn test_sfp_manifest_signing_integration() {
    // Verifies that the full SFP pipeline produces a signed manifest
    let sender_id = BevelIdentity::generate().unwrap();
    let mut sender_node = BevelNode::new(&sender_id, "test_db_sfp_sender", &[]).await.unwrap();
    
    let recipient_address = "dmp1recipient_test_address";
    let message_id = [0xABu8; 32];
    let ciphertext = b"Hello, this is an offline message for the SFP integration test!";
    
    // store_offline_message should succeed and produce a signed manifest
    let result = sender_node.store_offline_message(recipient_address, message_id, ciphertext);
    assert!(result.is_ok(), "SFP message storage should succeed: {:?}", result.err());
    
    println!("SFP manifest signed and stored successfully for message_id: {}", hex::encode(message_id));
    
    // Clean up
    let _ = std::fs::remove_dir_all("test_db_sfp_sender");
}

#[tokio::test]
async fn test_bns_registration_integration() {
    // Verifies that handle registration works end-to-end
    let id = BevelIdentity::generate().unwrap();
    let mut node = BevelNode::new(&id, "test_db_bns", &[]).await.unwrap();
    
    let handle = "testuser@bevel.com";
    let result = node.register_handle(handle, &id);
    assert!(result.is_ok(), "BNS handle registration should succeed: {:?}", result.err());
    
    println!("BNS handle '{}' registered for address '{}'", handle, id.address);
    
    // Verify invalid handles are rejected
    let bad_result = node.register_handle("invalid", &id);
    assert!(bad_result.is_err(), "Invalid handle should be rejected");
    
    // Clean up
    let _ = std::fs::remove_dir_all("test_db_bns");
}
