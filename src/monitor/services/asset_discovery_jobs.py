"""Bounded, durable discovery jobs. Retrying persistence never scans again."""
import concurrent.futures
import ipaddress
import json
import uuid
from datetime import datetime, timedelta
from monitor.domain.models import utc_now

RFC1918 = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))

def validate_network(value):
    network=ipaddress.ip_network(str(value).strip(),strict=False)
    if network.version!=4 or not any(network.subnet_of(n) for n in RFC1918):
        raise ValueError('仅允许 RFC1918 内网网段')
    if network.num_addresses>256:
        raise ValueError('单次最多 /24（256 个地址），请缩小网段')
    return network

class DiscoveryJobs:
    def __init__(self,db,probe,save):
        self.db,self.probe,self.save=db,probe,save
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=1,thread_name_prefix='asset-job')

    def get(self,job_id,ws):
        with self.db.connect() as conn:
            row=conn.execute('SELECT * FROM asset_discovery_jobs WHERE id=? AND workspace_id=?',(job_id,ws)).fetchone()
        if not row: return None
        result=dict(row)
        if result['status'] in ('queued','running') and datetime.fromisoformat(result['updated_at']) < utc_now()-timedelta(minutes=15):
            result['status']='interrupted'
            result['error']='任务已中断；完整结果可重试保存，未完成探测需重新发起'
        result['result']=json.loads(result.pop('result_json'))
        result.pop('request_json')
        return result

    def submit(self,body,ws,actor):
        network=validate_network(body.get('network',''))
        methods=(['icmp'] if body.get('ping',True) else [])
        ports=([22] if body.get('ssh',True) else [])+([3389] if body.get('rdp',True) else [])
        if ports:methods.append('tcp')
        if not methods:raise ValueError('至少选择一种探测方式')
        body={**body,'network':str(network),'_probe':{'methods':methods,'ports':ports,'success_policy':'any',
            'timeout_seconds':max(.5,min(5,float(body.get('timeout_seconds',1.5))))}}
        job_id=str(uuid.uuid4());now=utc_now().isoformat()
        with self.db.transaction(immediate=True) as conn:
            # A stopped API must not leave admission permanently blocked. Never
            # automatically repeat an interrupted scan after a restart.
            conn.execute("UPDATE asset_discovery_jobs SET status='interrupted',error='任务中断，请重新发起或重试保存' WHERE status IN ('queued','running') AND updated_at<?",
                ((utc_now()-timedelta(minutes=15)).isoformat(),))
            if conn.execute("SELECT count(*) FROM asset_discovery_jobs WHERE status IN ('queued','running')").fetchone()[0]>=2:
                raise ValueError('已有探测任务运行或排队，请稍后重试')
            conn.execute('INSERT INTO asset_discovery_jobs(id,workspace_id,actor,status,request_json,total,created_at,updated_at) VALUES(?,?,?,\'queued\',?,?,?,?)',
                (job_id,ws,actor,json.dumps(body),len(list(network.hosts())),now,now))
        self.executor.submit(self.run,job_id)
        return self.get(job_id,ws)

    def retry(self,job_id,ws):
        with self.db.transaction(immediate=True) as conn:
            cutoff=(utc_now()-timedelta(minutes=15)).isoformat()
            conn.execute("UPDATE asset_discovery_jobs SET status='interrupted' WHERE id=? AND workspace_id=? AND status IN ('queued','running') AND updated_at<?",(job_id,ws,cutoff))
            if conn.execute("SELECT count(*) FROM asset_discovery_jobs WHERE status IN ('queued','running') AND updated_at>=?",(cutoff,)).fetchone()[0]>=2:
                raise ValueError('已有探测任务运行或排队，请稍后重试')
            row=conn.execute('SELECT * FROM asset_discovery_jobs WHERE id=? AND workspace_id=?',(job_id,ws)).fetchone()
            if not row or row['status'] not in ('save_failed','interrupted') or not json.loads(row['result_json']).get('scan_complete'):
                raise ValueError('该任务没有可重试保存的完整探测结果')
            conn.execute("UPDATE asset_discovery_jobs SET status='queued',updated_at=?,error='' WHERE id=?",(utc_now().isoformat(),job_id))
        self.executor.submit(self.run,job_id,True)
        return self.get(job_id,ws)

    def update(self,job_id,**values):
        if not set(values).issubset({'status','progress','total','result_json','error','updated_at'}):
            raise ValueError('unsupported discovery job field')
        values['updated_at']=utc_now().isoformat()
        with self.db.transaction(immediate=True) as conn:
            conn.execute('UPDATE asset_discovery_jobs SET '+','.join(k+'=?' for k in values)+' WHERE id=?',(*values.values(),job_id))  # SQL structure uses fixed internal identifiers/clauses; values are bound separately.  # nosec B608

    def run(self,job_id,save_only=False):
        complete=False
        try:
            with self.db.connect() as conn:row=dict(conn.execute('SELECT * FROM asset_discovery_jobs WHERE id=?',(job_id,)).fetchone())
            body=json.loads(row['request_json']);result=json.loads(row['result_json'])
            self.update(job_id,status='running',error='')
            if not save_only:
                hosts=[str(ip) for ip in validate_network(body['network']).hosts()]
                online=[];progress=0
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    futures={pool.submit(self.probe,ip,body['_probe']):ip for ip in hosts}
                    for future in concurrent.futures.as_completed(futures):
                        ip=futures[future];r=future.result();progress+=1
                        if r['online']:
                            tcp=r.get('tcp',{})
                            online.append({'ip':ip,'os_guess':'Windows' if tcp.get('3389') else 'Linux' if tcp.get('22') else '未知','detail':r['detail']})
                        if progress%8==0 or progress==len(hosts):self.update(job_id,progress=progress)
                result={'network':body['network'],'scanned':len(hosts),'online':len(online),'assets':online,'scan_complete':True}
                self.update(job_id,result_json=json.dumps(result))
            complete=True
            # Save assets, audit and completion atomically. A failed transaction
            # leaves the durable scan results available without double actions.
            with self.db.transaction(immediate=True,retries=8) as conn:
                saved=self.save(conn,body,row['workspace_id'],row['actor'],result)
                conn.execute("UPDATE asset_discovery_jobs SET status='completed',result_json=?,updated_at=?,error='' WHERE id=?",
                    (json.dumps(saved),utc_now().isoformat(),job_id))
        except Exception as exc:
            try:self.update(job_id,status='save_failed' if complete else 'failed',error=str(exc)[:300])
            except Exception:pass  # stale tasks become interrupted, never reported as successful  # Intentional fail-open parsing/enrichment or best-effort failure-state persistence.  # nosec B110
