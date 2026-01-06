/*-------------------------------------------------------------------------
 *
 * tests/unix_socket_tests_default_path.rs
 *
 * Tests Unix socket with default path configuration.
 *
 *-------------------------------------------------------------------------
 */

use bson::doc;
use std::path::Path;

pub mod common;

#[tokio::test]
async fn test_socket_file_exists_at_default_path() {
    let default_path = "/tmp/osddb.sock";
    let (_tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        None,
    )
    .await;

    assert!(Path::new(default_path).exists());
    assert!(unix.is_some());
}

#[tokio::test]
async fn test_can_connect_via_default_path() {
    let (_tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        None,
    )
    .await;

    let unix_client = unix.expect("Unix client should exist");
    let db_names = unix_client.list_database_names().await;
    assert!(db_names.is_ok());
}

#[tokio::test]
async fn test_tcp_and_unix_both_work() {
    let (tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        None,
    )
    .await;

    let unix_client = unix.expect("Unix client should exist");
    let tcp_db = tcp.database("test_both");
    let unix_db = unix_client.database("test_both");
    let tcp_coll = tcp_db.collection::<bson::Document>("test");
    let unix_coll = unix_db.collection::<bson::Document>("test");

    tcp_coll.insert_one(doc! { "via": "tcp" }).await.unwrap();
    unix_coll.insert_one(doc! { "via": "unix" }).await.unwrap();

    // Verify TCP-inserted data can be read via Unix socket
    let tcp_data = unix_coll.find_one(doc! { "via": "tcp" }).await.unwrap();
    let tcp_doc = tcp_data.expect("TCP document should exist");
    assert_eq!(tcp_doc.get_str("via").unwrap(), "tcp");

    // Verify Unix-inserted data can be read via TCP
    let unix_data = tcp_coll.find_one(doc! { "via": "unix" }).await.unwrap();
    let unix_doc = unix_data.expect("Unix document should exist");
    assert_eq!(unix_doc.get_str("via").unwrap(), "unix");
}
