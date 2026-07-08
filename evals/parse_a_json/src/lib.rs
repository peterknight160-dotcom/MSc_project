use serde::{Deserialize, Serialize};

#[derive(Debug, Clone,  Deserialize)]
pub struct Measurement {
    pub unit: String,
    pub value: f64,
}

#[derive(Debug, Clone,  Deserialize)]
pub struct VehicleTelemetry {
    pub air_intake_temp: Measurement,
    pub altitude: Measurement,
    pub ambient_air_temp: Measurement,
    pub barometric_pressure: Measurement,

    pub dtc_number: String,

    pub engine_coolant_temp: Measurement,
    pub engine_load_value: f64,
    pub engine_rpm: Measurement,
    pub engine_runtime: String,

    pub epoch: u64,
    pub equiv_ratio_value: f64,
    pub fuel_level_value: f64,

    pub intake_manifold_pressure: Measurement,

    pub latitude: f64,
    pub longitude: f64,

    pub maf: Measurement,

    #[serde(rename = "short term fuel trim bank 1")]
    pub short_term_fuel_trim_bank_1: f64,

    pub speed: Measurement,

    pub throttle_pos_value: f64,
    pub timing_advance_value: f64,

    pub vehicle_id: String,
}