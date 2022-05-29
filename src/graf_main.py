from data_scraping import trace_main
import graf_process_args

import sys
import docker


def start_grafana():
    client = docker.from_env()

    cont_list = client.containers.list(filters={'name': 'grafana'}, all=True)
    for c in cont_list:
        if c.name == 'grafana':
            state = c.attrs['State']
            if state['Status'] == 'exited':
                c.start()
            return

    client.containers.run(name="grafana", detach=True, ports={'3000/tcp': 3000}, image='grafana/grafana')


def restart_grafana():
    client = docker.from_env()

    cont_list = client.containers.list(filters={'name': 'grafana'}, all=True)
    for c in cont_list:
        if c.name == 'grafana':
            state = c.attrs['State']
            if state['Status'] == 'exited':
                c.start()
            if state['Status'] == 'running':
                c.kill()
                c.start()
            return

    client.containers.run(name="grafana", detach=True, ports={'3000/tcp': 3000}, image='grafana/grafana')


def kill_grafana():
    client = docker.from_env()

    cont_list = client.containers.list(filters={'name': 'grafana'}, all=True)
    for c in cont_list:
        if c.name == 'grafana':
            state = c.attrs['State']
            if state['Status'] == 'running':
                c.kill()
            return


if __name__ == '__main__':
    # get args dict
    args = graf_process_args.process_args()

    if args['restart_graf']:
        restart_grafana()
    else:
        start_grafana()

    try:
        # start tracing and poll new events
        trace_main.do_tracing(args)

    except KeyboardInterrupt:
        if args['kill_graf']:
            kill_grafana()

        sys.exit(0)
