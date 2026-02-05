pub mod create;
pub mod get;
pub mod rename;
pub mod revoke;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/key-management/1.0";

pub const CREATE_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/create-key";
pub const CREATE_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/create-key-result";

pub const GET_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/get-key";
pub const GET_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-key-result";

pub const RENAME_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/rename-key";
pub const RENAME_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/rename-key-result";

pub const REVOKE_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/revoke-key";
pub const REVOKE_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/revoke-key-result";
