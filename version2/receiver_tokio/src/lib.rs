use serde::{Deserialize};

#[derive(Debug, Clone,  Deserialize)]
pub struct Measurement {
    pub unit: String,
    pub value: f64,
}

//Need to make fields can be optional, as not all fields will be present in the JSON data.
#[derive(Debug, Clone,  Deserialize)]
pub struct VehicleTelemetry {
    pub air_intake_temp: Option<Measurement>,
    pub altitude: Option<Measurement>,
    pub ambient_air_temp: Option<Measurement>,
    pub barometric_pressure: Option<Measurement>,

    pub dtc_number: Option<String>,

    pub engine_coolant_temp: Option<Measurement>,
    pub engine_load_value: Option<f64>,
    pub engine_rpm: Option<Measurement>,
    pub engine_runtime: Option<String>,

    pub epoch: Option<u64>,
    pub equiv_ratio_value: Option<f64>,
    pub fuel_level_value: Option<f64>,

    pub intake_manifold_pressure: Option<Measurement>,

    pub latitude: Option<f64>,
    pub longitude: Option<f64>,

    pub maf: Option<Measurement>,

    #[serde(rename = "short term fuel trim bank 1")]
    pub short_term_fuel_trim_bank_1: Option<f64>,

    pub speed: Option<Measurement>,

    pub throttle_pos_value: Option<f64>,
    pub timing_advance_value: Option<f64>,

    pub vehicle_id: Option<String>,
}
/* 
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Measurement {
    pub unit: String,
    pub value: f64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VehicleTelemetry {
    pub air_intake_temp: Option<Measurement>,
    pub altitude: Option<Measurement>,
    pub ambient_air_temp: Option<Measurement>,
    pub barometric_pressure: Option<Measurement>,

    pub dtc_number: Option<String>,

    pub engine_coolant_temp: Option<Measurement>,
    pub engine_load_value: Option<f64>,
    pub engine_rpm: Option<Measurement>,

    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
} */