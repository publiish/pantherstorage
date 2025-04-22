use serde::Serialize;
use crate::models::brand::Brand;

#[derive(Debug, Serialize)]
pub struct BrandStatsResponse {
    pub id: i64,
    pub brand_name: String,
    pub brand_url: Option<String>,
    pub write_permission: bool,
    pub delete_permission: bool,
}

impl From<Brand> for BrandStatsResponse {
    fn from(b: Brand) -> Self {
        Self {
            id: b.id,
            brand_name: b.brand_name,
            brand_url: b.brand_url,
            write_permission: b.write_permission,
            delete_permission: b.delete_permission,
        }
    }
}
