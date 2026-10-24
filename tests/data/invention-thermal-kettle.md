# Invention description: Self-calibrating kettle temperature hold

Inventor: Test Person. Date: 24 October 2026. Confidential draft.

## Problem
Electric kettles that hold a set temperature drift by several degrees because the thermistor at the base reads the
heating plate, not the water. Green and white teas are spoiled by water a few degrees too hot.

## The invention
A kettle with two sensors: a thermistor under the heating plate and an infrared sensor in the lid aimed at the water
surface. During the first heat-up of each fill, the controller records both readings and fits a simple correction
curve (plate reading to water temperature) for that fill volume, estimated from the time the water took to rise by
10 degrees. While holding, the heater is pulsed using the corrected estimate, so the water stays within 1 degree of
the target. The correction is re-fitted every fill, so scale build-up on the plate is compensated automatically.

## Variants
- The lid sensor may be replaced by a second thermistor on a probe that hangs into the water.
- The fill volume may be measured by a load cell in the base instead of estimated from heat-up time.

## Advantages
Accurate holding temperature without a probe touching the water; compensates for scale; low-cost parts.
