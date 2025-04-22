use crate::models::brand::{BrandProfileUpdate, BrandStatsResponse};
use crate::errors::ServiceError;
use mysql_async::{prelude::*, Conn};
use mysql_async::params;

pub async fn get_brand_stats(
    conn: &mut Conn,
    brand_id: i64,
) -> Result<BrandStatsResponse, ServiceError> {
    let brand: Option<(i64, String, Option<String>)> = conn
        .exec_first(
            "SELECT id, brand_name, brand_url FROM brands WHERE id = :id",
            params! { "id" => brand_id },
        )
        .await?;

    let (id, brand_name, brand_url) = brand.ok_or(ServiceError::InvalidInput(
        "Brand not found".to_string(),
    ))?;

    Ok(BrandStatsResponse {
        id,
        brand_name,
        brand_url,
    })
}

pub async fn update_brand_profile(
    conn: &mut Conn,
    brand_id: i64,
    profile_data: BrandProfileUpdate,
) -> Result<(), ServiceError> {
    conn.exec_drop(
        "UPDATE brands SET brand_name = :brand_name, brand_url = :brand_url, sub_domain = :sub_domain, write_permission = :write_permission, delete_permission = :delete_permission WHERE id = :id",
        params! {
            "id" => brand_id,
            "brand_name" => profile_data.brand_name,
            "brand_url" => profile_data.brand_url,
            "sub_domain" => profile_data.sub_domain,
            "write_permission" => profile_data.write_permission,
            "delete_permission" => profile_data.delete_permission,
        },
    )
    .await?;

    Ok(())
}

pub async fn register_brand_did(
    conn: &mut Conn,
    brand_id: i64,
    did_value: String,
) -> Result<(), ServiceError> {
    conn.exec_drop(
        "UPDATE brands SET did = :did WHERE id = :id",
        params! {
            "id" => brand_id,
            "did" => did_value,
        },
    )
    .await?;

    Ok(())
}
