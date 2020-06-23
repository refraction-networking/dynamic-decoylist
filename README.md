# Dynamic Decoy Lists Generator For TapDance

This program benches sub-par decoys for each country to lower the perceived failure rate.

## Prerequisite
- OS must support Shell, Go, Python3
- An SSH key with access to <https://github.com/refraction-networking/decoy-lists>
- An SSH key with access to the log server 


## Installation & Usage
Clone the repo and its dependencies

```go get -d -u -t github.com/refraction-networking/dynamic-decoylist/...```

```cd ${GOPATH:-~/go}/src/github.com/refraction-networking/dynamic-decoylist/runanalyser```

```go run main.go```



## How It Works
When running, the program will update the active decoy lists once per day at 5 minutes past midnight. The program fetches the newest decoy list and yesterday's log.
Using the average failure rate for each country, the program then uses a state machine to decide the status of each decoy. 

The penalty threshold is set as the average failure rate (#faileddecoys / (#failleddecoys + #newflows)) + ``const amnesty`` (default = 0.05)

- If a decoy is not on parole and under the penalty threshold, the decoy remains on the active duty list. 
- If a decoy is on parole and under the penalty threshold, the decoy remains on the active duty list. Its future benching period is shortened by one day. If its future benching period is zero, it will be excluded from the bench list. 
- If a decoy is on parole and above the penalty threshold, the decoy gets benched for the future benching period. Its future benching period doubles. 
- If a decoy is not on parole and above the penalty threshold, the decoy gets benched for one day. Its future benching period is two days. 
- If a decoy is benched, Its remaining day is shortened by one day. If the days remaining is zero, the decoy is added to the active duty list. 

The program left joins the up-to-date decoy list with decoys not benched for each country, and output the active duty list in `/list/`.

## TODO
Where to run this? (on each station or in a centralized location) 

Performance penalty of country look-up per connection? 

How to convert active list to blob? 

Is any of these a good idea?

## License
[MIT](https://choosealicense.com/licenses/mit/)
