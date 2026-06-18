use core::f64;
use std::char;
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


use plotters::prelude::*;

pub fn draw_histogram_from_btree(input:& BTreeMap<u128, u32>, legend: &str) -> Result<(), Box<dyn std::error::Error>> {

    let chart_name = format!("C:\\Users\\peter\\dissertation\\code\\graphs\\hist_{}.png", legend);
    let root = BitMapBackend::new(&chart_name, (640, 480)).into_drawing_area();
    root.fill(&WHITE)?;

    



    // Convert BTreeMap to Vec<(u128, u32)>
    let data: Vec<(u128, u32)> = input.iter().map(|(&k, &v)| (k, v)).collect();
    // Get x and y ranges for the chart
    let x_range = data.iter().map(|(x, _)| *x).collect::<Vec<u128>>();
    let y_range = data.iter().map(|(_, y)| *y).collect::<Vec<u32>>();
    let x_min =0;
    let x_max = *x_range.iter().max().unwrap_or(&0);
    let y_min = 0;
    let y_max = *y_range.iter().max().unwrap_or(&0);
    

let mut chart = ChartBuilder::on(&root)
        .caption(legend, ("sans-serif", 30))
        .margin(20)
        .x_label_area_size(30)
        .y_label_area_size(40)
        .build_cartesian_2d(x_min..x_max, y_min..y_max)?;


    chart.configure_mesh().draw()?;

    chart.draw_series(
        data.iter().map(|(x, y)|
            Rectangle::new([(*x - 2, 0), (*x + 2, *y)], BLUE.filled())
        )
    )?;

    Ok(())
}
