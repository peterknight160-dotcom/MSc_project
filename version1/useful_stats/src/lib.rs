use core::f64;
use std::fmt::{self, Display, Formatter};
use std::collections::BTreeMap;
pub struct  StatsResult {
    legend: String  ,
    elements: u32 , // Number of elements found
    minimum: u128, // Smallest element
    maximum: u128, // Largest element
    mean:  f64 ,
    std_dev: f64,
    percentiles: [u32; 15], // Percentiles to calculate
}

const PERCENTILE_TO_CALC: [u32; 15] = [1,2,5,10,20,30,40,50,60,70,80,90, 95,98, 99];


impl Display for StatsResult {
    fn fmt (&self, f: &mut Formatter ) -> fmt::Result {
        let _ = write! ( f, "For {}:: elements: {}  mean: {:.2} std_dev: {:.2}", self.legend, self.elements, self.mean , self.std_dev);
        writeln!(f, " Minimum: {} ,  maximum: {} ,  percentiles: {:?}    ", self.minimum, self.maximum, self.percentiles)
    }
}



pub fn stats_from_btree ( input:BTreeMap<u128, u32>, legend: &str ) -> StatsResult {
 // Calculate the mean from the hash
    let mut x: u128 = 0;
    let mut elements: u32 = 0 ;
  
    let mut min: u128 = 1000000;
    let mut max: u128 = 0;
    for val in input.keys() {
        let value= *val;
        let freq = *input.get(&val).unwrap() ;
        elements += freq;
   
        x +=  value * freq as u128; 
        match value > max {
            true => max = value, 
            false => () ,
        }
        match value < min  {
            true => min = value, 
            false => () ,
        }
    }
    let meanloop = (  x as f64)/( elements as f64);
 
  
    // Calculate std deviation, percentiles, etc
    let mut sumsquares:f64 = 0.0;
   
    let mut elements_so_far : f64 = 0.0 ;
    let mut percentiles: [u32; 15] = [0; 15];
    for val in input.keys(){
        let value= *val as f64;
        let freq = *input.get(&val).unwrap() ;
        sumsquares += (value - meanloop)*( value  - meanloop) * freq as f64  ;
        elements_so_far += freq as f64 ;
        for (i, p) in PERCENTILE_TO_CALC.iter().enumerate() {
            if elements_so_far as f64 >= *p as f64 * elements as f64 / 100.0 && percentiles[i] == 0 {
                percentiles[i] = *val as u32;
            }
        }
        
    }    
  
    let std_dev = (sumsquares / elements as f64).sqrt();    
  

    

    return StatsResult {
        legend: legend.to_string(),
        elements: elements,
        minimum: min,
        maximum: max,
        mean: meanloop,
        std_dev: std_dev,
        percentiles: percentiles
    }
    


}


