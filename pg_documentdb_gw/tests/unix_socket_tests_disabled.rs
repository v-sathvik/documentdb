/*-------------------------------------------------------------------------
 *
 * tests/unix_socket_tests_disabled.rs
 *
 * Tests Unix socket when disabled.
 *
 *-------------------------------------------------------------------------
 */

use bson::doc;
use std::path::Path;

pub mod common;

#[tokio::test]
async fn test_disabled_ignores_path() {
    let should_ignore_path = "/tmp/should_not_exist.sock";
    let (tcp, unix) = common::initialize_with_config_and_unix(
        Some(false),
        Some(should_ignore_path.to_string()),
    )
    .await;

    assert!(!Path::new(should_ignore_path).exists());
    assert!(unix.is_none());

    let db = tcp.database("test_disabled");
    let coll = db.collection::<bson::Document>("test");
    coll.insert_one(doc! { "test": "tcp works" }).await.unwrap();
    let result = coll.find_one(doc! { "test": "tcp works" }).await.unwrap();
    let doc = result.expect("Document should exist");
    assert_eq!(doc.get_str("test").unwrap(), "tcp works");
}

#[tokio::test]
async fn test_disabled_by_default() {
    // Clean up socket files from other test files (they never shutdown)
    let _ = std::fs::remove_file("/tmp/osddb.sock");
    let _ = std::fs::remove_file("/tmp/custom_osddb.sock");

    let (tcp, unix) = common::initialize_with_config_and_unix(
        None,
        None,
    )
    .await;

    assert!(unix.is_none());
    assert!(!Path::new("/tmp/osddb.sock").exists());

    let db = tcp.database("test_default");
    let coll = db.collection::<bson::Document>("test");
    coll.insert_one(doc! { "test": "tcp works" }).await.unwrap();
    let result = coll.find_one(doc! { "test": "tcp works" }).await.unwrap();
    let doc = result.expect("Document should exist");
    assert_eq!(doc.get_str("test").unwrap(), "tcp works");
}

#[tokio::test]
async fn test_tcp_works_when_disabled() {
    let (tcp, unix) = common::initialize_with_config_and_unix(
        Some(false),
        None,
    )
    .await;

    assert!(unix.is_none());

    let db = tcp.database("test_tcp_only");
    let coll = db.collection::<bson::Document>("test");
    coll.insert_one(doc! { "test": "data" }).await.unwrap();
    let result = coll.find_one(doc! { "test": "data" }).await.unwrap();
    let doc = result.expect("Document should exist");
    assert_eq!(doc.get_str("test").unwrap(), "data");
}
