use core::f64;
use std::fmt::{self, Display, Formatter};
use std::collections::BTreeMap;
pub struct  StatsResult {
    legend: String  ,
    elements: u32 , // Number of elements found
    minimum: u128, // Smallest element
    maximum: u128, // Smallest element
    mean:  f64 ,
    std_dev: f64,
    ninety_pct: u128,
    ninety_nine_pct: u128
}

impl Display for StatsResult {
    fn fmt (&self, f: &mut Formatter ) -> fmt::Result {
        let _ = write! ( f, "For {}:: elements: {}  mean: {:.2} std_dev: {:.2}", self.legend, self.elements, self.mean , self.std_dev);
        writeln!(f, " Minimum: {} ,  maximum: {} , 90th percentile: {}   99th percentile: {} ", self.minimum, self.maximum, self.ninety_pct, self.ninety_nine_pct)
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
 
  
    // Calculate std deviation, 90 & 99 Percentiles
    let mut sumsquares:f64 = 0.0;
    let ninety = (elements *  90 ) /100 ;
    let ninetynine = (elements *  99 ) /100;
    let mut elements_so_far : u32 = 0 ;
    let mut  ninety_pct = 0 ;
    let mut ninetynine_pct = 0 ;

    for val in input.keys(){
        let value= *val as f64;
        let freq = *input.get(&val).unwrap() ;
        sumsquares += (value - meanloop)*( value  - meanloop) * freq as f64  ;
        elements_so_far += freq ;
        if elements_so_far >=  ninety && ninety_pct == 0 {
            ninety_pct= *val
            
            ;

        }
        if elements_so_far >=  ninetynine && ninetynine_pct == 0 {
            ninetynine_pct= *val;
            
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
        ninety_pct: ninety_pct , 
        ninety_nine_pct: ninetynine_pct 
    }
    


}


