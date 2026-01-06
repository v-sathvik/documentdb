/*-------------------------------------------------------------------------
 *
 * tests/unix_socket_tests_custom_path.rs
 *
 * Tests Unix socket with custom path configuration.
 *
 *-------------------------------------------------------------------------
 */

use bson::doc;
use std::path::Path;

pub mod common;

#[tokio::test]
async fn test_socket_file_exists_at_custom_path() {
    let custom_path = "/tmp/custom_osddb.sock";
    let (_tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        Some(custom_path.to_string()),
    )
    .await;

    assert!(Path::new(custom_path).exists());
    assert!(unix.is_some());
}

#[tokio::test]
async fn test_can_connect_via_custom_path() {
    let custom_path = "/tmp/custom_osddb.sock";
    let (_tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        Some(custom_path.to_string()),
    )
    .await;

    let unix_client = unix.expect("Unix client should exist");
    let db_names = unix_client.list_database_names().await;
    assert!(db_names.is_ok());
}

#[tokio::test]
async fn test_operations_work_via_custom_path() {
    let custom_path = "/tmp/custom_osddb.sock";
    let (_tcp, unix) = common::initialize_with_config_and_unix(
        Some(true),
        Some(custom_path.to_string()),
    )
    .await;

    let unix_client = unix.expect("Unix client should exist");
    let db = unix_client.database("test_custom_ops");
    let coll = db.collection::<bson::Document>("test");

    coll.insert_one(doc! { "test": "data" }).await.unwrap();
    let result = coll.find_one(doc! { "test": "data" }).await.unwrap();
    let doc = result.expect("Document should exist");
    assert_eq!(doc.get_str("test").unwrap(), "data");
}
