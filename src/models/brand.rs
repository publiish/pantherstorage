use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize)]
pub struct Brand {
    pub id: i64,
    pub brand_name: String,
    pub brand_url: Option<String>,
    pub magic_link_id: String,
    pub did: Option<String>,
    pub dao_id: Option<i64>,
    pub sub_domain: Option<String>,
    pub write_permission: bool,
    pub delete_permission: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BrandProfileUpdate {
    pub brand_id: i64,

    #[validate(length(min = 1))]
    pub brand_name: String,

    pub brand_url: Option<String>,
    pub sub_domain: Option<String>,
    pub write_permission: bool,
    pub delete_permission: bool,
}

#[derive(Debug, Serialize)]
pub struct BrandStatsResponse {
    pub id: i64,
    pub brand_name: String,
    pub brand_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BrandRegisterRequest {
    pub brand_id: i64,

    #[validate(length(min = 1))]
    pub did: String,
}
