/*-------------------------------------------------------------------------
 *
 * tests/isdbgrid_tests_disabled.rs
 *
 * Tests isdbgrid when disabled.
 *
 *-------------------------------------------------------------------------
 */

use bson::doc;

pub mod common;

#[tokio::test]
async fn test_isdbgrid_disabled() {
    let mut config = common::setup_configuration();
    config.is_mongo_sharded = Some(false);

    let client = common::initialize_with_config(config).await;
    let db = client.database("test_isdbgrid_disabled");

    let hello_result = db.run_command(doc! { "hello": 1 }).await.unwrap();
    assert!(
        !hello_result.contains_key("msg"),
        "hello should NOT contain 'msg' field when isdbgrid is disabled"
    );
    assert_eq!(hello_result.get_f64("ok").unwrap(), 1.0);
}

#[tokio::test]
async fn test_isdbgrid_command_fails_when_disabled() {
    let mut config = common::setup_configuration();
    config.is_mongo_sharded = Some(false);

    let client = common::initialize_with_config(config).await;
    let db = client.database("test_isdbgrid_command_disabled");

    // When disabled, isdbgrid command should fail with error (like mongod)
    let result = db.run_command(doc! { "isdbgrid": 1 }).await;
    assert!(
        result.is_err(),
        "isdbgrid command should fail when disabled"
    );

    // Verify the error message contains the expected text
    let error = result.err().unwrap();
    let error_string = error.to_string();
    assert!(
        error_string.contains("no such cmd: isdbgrid") || error_string.contains("CommandNotFound"),
        "Error should indicate command not found, got: {}",
        error_string
    );
}
