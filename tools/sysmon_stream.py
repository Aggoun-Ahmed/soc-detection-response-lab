"""Session-scoped incremental Wazuh correlation; no persistence or response actions."""
from datetime import timedelta
from tools.sysmon_correlator import _object, _timestamp

class IncrementalCorrelator:
    """Join 100133 and 100134 by agent/ProcessGuid across batches (60 s default)."""
    def __init__(self, window_seconds=60, max_lateness_seconds=120, max_keys=10000):
        if not isinstance(window_seconds,int) or window_seconds <= 0: raise ValueError("invalid window")
        if not isinstance(max_lateness_seconds,int) or max_lateness_seconds < 0: raise ValueError("invalid lateness")
        if not isinstance(max_keys,int) or max_keys < 1: raise ValueError("invalid max_keys")
        self.window_seconds=window_seconds
        self.max_lateness_seconds=max_lateness_seconds
        self.max_keys=max_keys
        self.processes={}
        self.files={}
        self.emitted={}
        self.watermark=None

    def _prune(self):
        cutoff=self.watermark-timedelta(seconds=self.window_seconds+self.max_lateness_seconds)
        for store in (self.processes,self.files,self.emitted):
            for key,when in tuple(store.items()):
                if when < cutoff: del store[key]

    def ingest(self, alert):
        if not isinstance(alert,dict): return []
        rule=str(_object(alert.get("rule")).get("id",""))
        if rule not in ("100133","100134"): return []
        agent=_object(alert.get("agent")).get("id")
        event=_object(_object(_object(alert.get("data")).get("win")).get("eventdata"))
        guid=event.get("processGuid")
        when=_timestamp(alert)
        if not isinstance(agent,str) or not agent.strip() or not isinstance(guid,str) or not guid.strip() or when is None: return []
        if self.watermark is None or when > self.watermark:
            self.watermark=when
            self._prune()
        if when < self.watermark-timedelta(seconds=self.window_seconds+self.max_lateness_seconds): return []
        key=(agent.strip(),guid.strip().lower())
        if key in self.emitted: return []
        if key not in self.processes and key not in self.files and len(self.processes)+len(self.files)+len(self.emitted)>=self.max_keys:
            raise RuntimeError("correlation key limit reached; stop rather than silently discard")
        if rule=="100133": self.processes[key]=min(self.processes.get(key,when),when)
        else: self.files[key]=min(self.files.get(key,when),when)
        if key not in self.processes or key not in self.files: return []
        delta=(self.files[key]-self.processes[key]).total_seconds()
        if not 0<=delta<=self.window_seconds: return []
        self.processes.pop(key);self.files.pop(key);self.emitted[key]=max(when,self.watermark)
        return [{"finding":"encoded_powershell_followed_by_lab_file_create","level":"investigate","matched_rules":["100133","100134"],"delta_seconds":round(delta,3),"guid_match":True,"agent_match":True}]

    def feed(self,alerts):
        if not isinstance(alerts,(list,tuple)): raise TypeError("alerts must be a list or tuple")
        findings=[]
        for alert in alerts: findings.extend(self.ingest(alert))
        return findings
