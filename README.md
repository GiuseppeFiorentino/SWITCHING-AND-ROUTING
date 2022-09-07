# **Project**: "Network Monitoring"
### Team 4: "Konstantinos Marios Roumpeas, Giuseppe Maria Fiorentino"

## **Description of the project**

The aim of the project is to design a multipath network (mininet topo), where there are multiple paths from one switch to another. On this topology a monitoring algorithm is implemented to collect the statistics of the flows from the switches. Every switch status is saved every 10 seconds. The algorithm is tested with different traffic generators (D-ITG, iperf) and the results are displayed on kernel and stored in csv files for further analysis.

## **Description of the repository**

- **sar_application_SDN.py**:
The monitoring part of the file consists of 3 parts:
- **Fixed-Cycle Processing**:
    - Triggered by EventOFPStateChange.
    - Monitoring the state of a Datapath so it is retrieved when a switch is registered, or its registration is deleted.
    - Request statistical information of registered switched, infinitely every 10 seconds.
    - OFPFlowStatsRequest requests that the switch provides statistical information related to flow entry. The requested target flow entry can be narrowed down by conditions such as table ID, output port, cookie value and match but here all entries are made subject to the request.
    - OFPPortStatsRequest request that the switch provides port-related statistical information. It is possible to specify the desired port number to acquire information from. Here, OFPP_ANY is specified to request information from all ports.

- **FlowStats**:
    - Triggered by EventOFPFlowStatsReply.
    - All flow entries are selected and sorted based on priority. Priority 0 is the Table-miss flow.
    - EventOFPFlowStatsReply class’s attribute body is the list of OFPFlowStats and stores the statistical information of each flow entry, which was subject to FlowStatsRequest.
    - Flow statistics retrieved per datapath:
        - table_id: ID of the table the flow came from.
        - duration_sec: Time flow has been alive in seconds.
        - duration_nsec: Time flow has been alive in nanoseconds beyond duration_sec.
        - priority: Specifies the priority order of this entry. The greater the value, the higher the priority.
            - The Table-miss flow entry has the lowest (0) priority and this entry matches all packets.
        - idle_timeout: Number of seconds idle before expiration.
        - hard_timeout: Number of seconds before expiration.
        - cookie: Opaque controller-issued identifier.
        - packet_count: Number of packets in the flow.
        - byte_count: Number of bytes in the flow.

- **PortStats**:
    - Triggered by EventOFPPortStatsReply.
    - OPFPortStatsReply class’s attribute body is the list of OFPPortStats.
    - The statistical information is outputted based on port number.
    - Statistical information retrieved per Datapath:
        - port: Port numbers.
        - rx-pkts: receive packet count.
        - rx-bytes: received bytes count
        - rx-error: receive error count.
        - rx-drop: received drop count.
        - tx-pkts: send packet count.
        - tx-bytes sent bytes count
        - tx-error: send error count.
        - tx-drop: send drop count.

The data retrieved during the monitoring period are being stored in `Flowstats.csv` and `Portstats.csv` respectively.
    

- **topology_1.py**:
This script contains a custom topology consisting of 12 hosts, each one attached to a switch (12 switches in total). The topology structured consists of 12 switches whose interconnection offers multiple paths:
- s1 <--> s2
- s2 <--> s3
- s1 <--> s6
- s3 <--> s4
- s3 <--> s5
- s4 <--> s5
- s4 <--> s6
- s5 <--> s7
- s7 <--> s8
- s7 <--> s12
- s8 <--> s9
- s9 <--> s10
- s10 <--> s11
- s11 <--> s12
    

- **stat_management.ipynb**:
The purpose of this script is to analyze and interpret the information obtained during the monitoring period. `FlowStats.csv` and `PortStats.csv` are being fed. The following plots are being illustrated per file:
    - **Flowstats.csv**:
        - Flow duration in sec during the monitoring period.
        - The variation of throughput in byte/sec during the monitoring period.
        - Byte count in time.
        - Packet count in time.
        - Packet count per datapath.
        - Frequency of each priority appearance in percentage.
    - **Portstats.csv**:
        - Transmitted vs received packets per datapath (12 plots in total, one per datapath).
        - Incoming vs outgoing traffic per port in packets.

The goal of the project was to interpret all the data obtained. In order to better characterize the network it is retrieved also the
datapath of the flows going though it.
In order to get all the network informations the stat_management.ipynb needs to be run. It will process the flowstats and portstats files giving as output
all the meaningful monitoring informations.


## **How to run the project**

In order to run the project the following steps should  be followed:

- Open the VM and use the credentials:
    - ryu login: ryu
    - Password: ryu
- In 2 different terminals run: 

```
ssh -X ryu@127.0.0.1 -p 2222
```
    
where -X is required to enter the hosts using `xterm`.
- Use the same credentials as step 1 to enter.
- In one of the 2 terminals run one of the following command sets based on the existance or not of the repository:
    - If a fresh installation is needed: 

    ```
    git clone https://gitlab.com/switching-and-routing-polimi-code-repository/2020-2021/team-4.git
    ```

    - If the repository  is already present:

        ```
        cd team-4
        git pull
        cd ..
        ```

- The Ryu controller should be initialized first in the first terminal:

    ```
    PYTHONPATH=. ./ryu/bin/ryu-manager --observe-links team-4/sar_application_SDN.py
    ```

- And then the mininet topology should be created on the second one:

    ```
    sudo mn --custom team-4/topology_1.py --topo mytopo --controller=remote,ip=10.0.2.15,port=6633 --switch ovs,protocols=OpenFlow13
    ```

- Some of the commands that can run in the mininet kernel:
    - In order all hosts ping one another.

    ```
    pingall
    ```

    - So that host id1 pings host id2.

    ```
    <host id1> ping <host id2>
    ```

    - In order to enter the hosts with id1 and id2 in 2 different kernels and customize their communication:

    ```
    xterm <host id1 host id2>
    ```

    - For UDP:
        - In `host id1`:

        ```
        iperf -s -u -p 2222
        ```
        
        to set as server
        - In `host id2`:

        ```
        iperf -c 10.0.0.1 -u -b 10M -t 60 -p 2222 
        ```
            
        to set as client
    - For TCP:
        - In `host id1`:

        ```
        iperf -s -p 2222 
        ```

        to set as server
        - In `host id2`:

        ```
        iperf -c 10.0.0.1 -b 10M -t 60 -p 2222 
        ```
            
        to set as client 

Finally, [run the jupyter notebook](https://www.youtube.com/watch?v=h1sAzPojKMg "jupyter notebook tutorial") `stat_management.ipynb`, on the localhost to further analyse the retrieved data.

**Note**: Before running the implementation, always erase both `FlowStats.csv` and `PortStats.csv`, if they already exist in the folder. The files are not ovewritten, something that ends up to a corrupted dataset.


## **Results**
Sereval plots have been made, not only based on the datapath of a certain flow but also characterized by the flow's priority. Three different priorities 
have been found: 0,1,65355. It has been observed that flows with priorities 0 (the Table-miss flow entry) and 65355 are always present in the switches and they are irrelevant to the traffic exchange between two or more hosts. On the other hand, packets characterized by priority 1 are marked as active communication between two or more hosts.
The quantity of data sent through the network is also a crucial information to monitor. For this reason in the plots are included the packet count and byte count per datapath. A general observation made, is that switches located in the middle of the topology, carry in general more traffic (both incoming and outgoing). This outcome is expected since they are both involved with the traffic that has to do with host directly connected to them and also act as middlemen for edge hosts communication.
Moreover for each datapath it is shown the number of transmitted and received packets per port. An interesting remark is that that port 1 is involved more in outgoing than incoming traffic, while ports 2 and 3 balance their load between both.
The results obtained were in line with what expected considering also the topology of the network.
