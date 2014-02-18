#!/bin/bash
../cake CakeResque.CakeResque stop --all
../cake CakeResque.CakeResque start --interval 5 --queue default
../cake CakeResque.CakeResque start --interval 5 --queue cache
../cake CakeResque.CakeResque start --interval 5 --queue email
../cake CakeResque.CakeResque startscheduler -i 5
