const JSON: &str = "{
    \"air_intake_temp\": {
        \"unit\": \"C\",
        \"value\": 33
    },
    \"altitude\": {
        \"unit\": \"m\",
        \"value\": 37
    },
    \"ambient_air_temp\": {
        \"unit\": \"C\",
        \"value\": 28
    },
    \"barometric_pressure\": {
        \"unit\": \"kPa\",
        \"value\": 100
    },
    \"dtc_number\": \"MIL is OFF0 codes\",
    \"engine_coolant_temp\": {
        \"unit\": \"C\",
        \"value\": 84
    },
    \"engine_load_value\": 0.604,
    \"engine_rpm\": {
        \"unit\": \"RPM\",
        \"value\": 2017
    },
    \"engine_runtime\": \"00:09:21\",
    \"epoch\": 1513362278,
    \"equiv_ratio_value\": 0.01,
    \"fuel_level_value\": 0.706,
    \"intake_manifold_pressure\": {
        \"unit\": \"kPa\",
        \"value\": 38
    },
    \"latitude\": -3.519648,
    \"longitude\": -58.576573,
    \"maf\": {
        \"unit\": \"g/s\",
        \"value\": 18
    },
    \"short term fuel trim bank 1\": -0.062,
    \"speed\": {
        \"unit\": \"km/h\",
        \"value\": 61
    },
    \"throttle_pos_value\": 0.325,
    \"timing_advance_value\": 0.686,
    \"vehicle_id\": \"AZ40EUA\"
}";

use serde_json::Result;
use parse_a_json::VehicleTelemetry;




fn main() {
 // Convert the JSON string to a VehicleTelemetry struct
    let telemetry: Result<VehicleTelemetry> = serde_json::from_str(JSON);
    let telemetry = match telemetry {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            return;
        }
    };
    
    println! ("Speed is: {}", telemetry.speed.value);
    println!("Speed unit is: {}", telemetry.speed.unit);
    println! ("Epoch is: {}", telemetry.epoch);
    println! ("Vehicle ID is: {}", telemetry.vehicle_id);

}
