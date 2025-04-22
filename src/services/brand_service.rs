use crate::{
    database::{get_brand_stats, register_brand_did, update_brand_profile},
    errors::ServiceError,
    models::brand::{BrandProfileUpdate, BrandStatsResponse},
};
use mysql_async::Pool;

pub struct BrandService {
    pub db_pool: Pool,
}

impl BrandService {
    pub fn new(db_pool: Pool) -> Self {
        Self { db_pool }
    }

    pub async fn get_brand_stats(&self, brand_id: i64) -> Result<BrandStatsResponse, ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        get_brand_stats(&mut conn, brand_id).await
    }

    pub async fn update_brand_profile(
        &self,
        brand_id: i64,
        profile_data: BrandProfileUpdate,
    ) -> Result<(), ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        update_brand_profile(&mut conn, brand_id, profile_data).await
    }

    pub async fn register_brand_did(&self, brand_id: i64, did: String) -> Result<(), ServiceError> {
        let mut conn = self.db_pool.get_conn().await?;
        register_brand_did(&mut conn, brand_id, did).await
    }
}
