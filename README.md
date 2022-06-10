# App-Tracer
Instrument for tracing apps using eBPF. App Tracer can visualize data, export it and send alerts about crucial events via Telegram.  
## Configuring
Uses [BCC](https://github.com/iovisor/bcc) for working with eBPF, [Prometheus](https://prometheus.io) for storing data, [Grafana](https://grafana.com) for visualiation and [Alertmanager](https://github.com/prometheus/alertmanager) for Telegram alerts. Before using App Tracer make sure you have them all installed. By default Prometheus can be found at localhost:9090, Alertmanager at localhost:9093, Grafana at localhost:3000.  
To configure Telegram alerts insert bot token in its field in [alertmanager.yml](src/alertmanager.yml) and start Alertmanager.  
## Usage
For loading eBPF program to kernel super user permission is necessary, so you can run the program only with them.  
To start tracing just run `trace.sh` or `graf_trace.sh`. For example to trace process with PID 9234, update data every 4 seconds and show in Grafana:
```
./graf_trace.sh -p 9234 -u 4
```
You can use `-h` to view examples and all possible options.  
`tcp_trace.sh` works almost the same as tcpdump does.  
Examples of Grafana dashboards:  
<p align="center"><img src="https://github.com/ComradeAndrewQS37/App-Tracer/blob/main/screenshots/cpu_usage.png" height=400></p>
<p align="center"><img src="https://github.com/ComradeAndrewQS37/App-Tracer/blob/main/screenshots/tcp_ip.png" height=404></p>
