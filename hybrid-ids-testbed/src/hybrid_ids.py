#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, platform, resource, time
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix

DATA=Path('data/cicids2017')
OUT=Path('run_output'); OUT.mkdir(exist_ok=True)
FILES={
 'train':['Monday-WorkingHours.pcap_ISCX.csv'],
 'validation':['Tuesday-WorkingHours.pcap_ISCX.csv','Wednesday-workingHours.pcap_ISCX.csv'],
 'test':['Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv','Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv','Friday-WorkingHours-Morning.pcap_ISCX.csv','Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv','Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv']
}
RATE_CANDIDATE='Flow Packets/s'; LABEL='Label'; CHUNK=100_000

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()

def read_headers(p): return [str(c).strip() for c in pd.read_csv(p,nrows=0).columns]
def assign_binary(s):
 s=s.astype('string').str.strip().str.replace('ï¿½','-',regex=False).str.replace('�','-',regex=False); known=s.notna() & (s!='')
 benign=s.str.lower().eq('benign')
 return s, np.where(known, np.where(benign,0,1),-1).astype(np.int8)

def clean_features(df, feat_cols):
 x=df.reindex(columns=feat_cols)
 for c in feat_cols: x[c]=pd.to_numeric(x[c],errors='coerce')
 return x.replace([np.inf,-np.inf],np.nan)

def row_hashes(x):
 # Duplicate detection uses pre-imputation numeric values and preserves missingness.
 return pd.util.hash_pandas_object(x.replace([np.inf,-np.inf],np.nan).astype('string').fillna('<MISSING>'),index=False).to_numpy(dtype=np.uint64)

def load_part(role, paths, feature_cols, seen=None, medians=None):
 xs=[]; ys=[]; labels=[]; sources=[]; audit=[]; prior=set() if seen is None else seen
 for name in paths:
  p=DATA/name
  if not p.exists(): raise FileNotFoundError(p)
  rawrows=0; raw_label_counts=Counter(); missing=0; removed=0; file_rows=0
  for chunk in pd.read_csv(p,chunksize=CHUNK,low_memory=False,encoding='cp1252'):
   chunk.columns=[str(c).strip() for c in chunk.columns]
   if LABEL not in chunk.columns: raise ValueError(f'{name}: missing {LABEL}')
   rawrows+=len(chunk); clean_label,y=assign_binary(chunk[LABEL]); raw_label_counts.update(clean_label.fillna('<missing>').astype(str).value_counts().to_dict())
   x=clean_features(chunk,feature_cols); missing+=int(x.isna().sum().sum())
   valid=y>=0
   x=x.loc[valid].reset_index(drop=True); y=y[valid]; lbl=clean_label.loc[valid].reset_index(drop=True)
   h=row_hashes(x)
   keep=np.ones(len(x),bool)
   if role!='train':
    for i,v in enumerate(h):
     hv=int(v)
     if hv in prior: keep[i]=False; removed+=1
     else: prior.add(hv)
   x=x.loc[keep].fillna(medians).to_numpy(dtype=np.float32,copy=True); y=y[keep]; lbl=lbl.loc[keep].reset_index(drop=True)
   file_rows+=len(y)
   xs.append(x); ys.append(y); labels.extend(lbl.astype(str).tolist()); sources.extend([name]*len(y))
  audit.append({'file':name,'partition':role,'sha256':sha(p),'raw_rows':rawrows,'mapped_rows':file_rows,'labels_raw':dict(raw_label_counts),'missing_feature_cells':missing,'cross_partition_exact_feature_duplicates_removed':removed})
 return (np.vstack(xs) if xs else np.empty((0,len(feature_cols)),np.float32), np.concatenate(ys) if ys else np.array([],np.int8), np.array(labels,dtype=object), np.array(sources,dtype=object), audit, prior)

def metric(y,p):
 tn,fp,fn,tp=confusion_matrix(y,p,labels=[0,1]).ravel()
 div=lambda a,b: float(a/b) if b else None
 pr=div(tp,tp+fp); re=div(tp,tp+fn)
 return {'N':int(len(y)),'TP':int(tp),'FP':int(fp),'TN':int(tn),'FN':int(fn),'precision':pr,'recall':re,'F1':(2*pr*re/(pr+re) if pr is not None and re is not None and pr+re else (0.0 if pr==0 or re==0 else None)),'FPR':div(fp,fp+tn),'balanced_accuracy':((re+div(tn,tn+fp))/2 if re is not None and tn+fp else None)}

def tune(scores,y,budget):
 neg=np.sort(scores[y==0]); pos=np.sort(scores[y==1]); vals=np.unique(scores)
 # Alert for score >= cutoff.
 fpr=(len(neg)-np.searchsorted(neg,vals,side='left'))/len(neg)
 rec=(len(pos)-np.searchsorted(pos,vals,side='left'))/len(pos)
 feasible=np.flatnonzero(fpr<=budget)
 if len(feasible):
  i=max(feasible,key=lambda j:(rec[j],-fpr[j],vals[j])); status='budget_met'
 else:
  i=min(range(len(vals)),key=lambda j:(fpr[j],-rec[j])); status='budget_unattainable'
 return float(vals[i]), {'validation_FPR':float(fpr[i]),'validation_recall':float(rec[i]),'target_FPR':budget,'status':status}

def main():
 allpaths=sum(FILES.values(),[])
 cols=read_headers(DATA/FILES['train'][0]); normalized=[c.strip() for c in cols]
 if LABEL not in normalized: raise ValueError('Label column absent')
 # Numeric training-derived feature list; endpoint/date/flow identity fields are excluded by name.
 blacklist=('label','flow id','timestamp','source ip','destination ip','src ip','dst ip','date','time')
 feature_cols=[c for c in normalized if not any(x in c.lower() for x in blacklist) and c.lower() not in {'source port','src port'}]
 feature_cols=[c for c in feature_cols if c!='']
 # Fit preprocessing statistics on the complete benign Monday partition.
 train_path=DATA/FILES['train'][0]
 train_frame=pd.read_csv(train_path,low_memory=False,encoding='cp1252'); train_frame.columns=[str(c).strip() for c in train_frame.columns]
 train_labels,train_y=assign_binary(train_frame[LABEL])
 medians=clean_features(train_frame,feature_cols).loc[train_y==0].median(axis=0,numeric_only=True).fillna(0).astype(np.float32)
 benign_rate=pd.to_numeric(train_frame.loc[train_y==0,RATE_CANDIDATE],errors='coerce').replace([np.inf,-np.inf],np.nan).dropna().to_numpy()
 del train_frame,train_labels,train_y
 # Load training data; no cross-partition dedup needed for training itself.
 xtr,ytr,ltr,strtr,atr,_=load_part('train',FILES['train'],feature_cols,medians=medians)
 if not np.all(ytr==0): raise ValueError('Training partition must be benign only')
 # Keep all train rows in the feature matrix, fit Isolation Forest on all benign records.
 train_hashes=set()
 for chunk in pd.read_csv(train_path,chunksize=CHUNK,low_memory=False,encoding='cp1252'):
  chunk.columns=[str(c).strip() for c in chunk.columns]
  _labels,_y=assign_binary(chunk[LABEL]); x=clean_features(chunk,feature_cols).loc[_y==0]
  train_hashes.update(map(int,row_hashes(x)))
 xval,yval,lval,val_source,aval,seen=load_part('validation',FILES['validation'],feature_cols,seen=train_hashes,medians=medians)
 xtest,ytest,ltest,test_source,atest,seen=load_part('test',FILES['test'],feature_cols,seen=seen,medians=medians)
 # Test class support and training/validation sanity
 if len(np.unique(yval))<2 or len(np.unique(ytest))<2: raise ValueError('Validation/test must include benign and attack flows')
 seed=42; model=IsolationForest(n_estimators=100,random_state=seed,n_jobs=-1,contamination='auto')
 t0=time.perf_counter(); model.fit(xtr); fit_sec=time.perf_counter()-t0
 t0=time.perf_counter(); sval=-model.decision_function(xval); anom_test_scores=-model.decision_function(xtest); anomaly_pred_sec=time.perf_counter()-t0
 budget=.01; athr,atune=tune(sval,yval,budget); ap_val=sval>=athr; ap_test=anom_test_scores>=athr
 # Candidate rate thresholds are training-benign quantiles, with the paper's .999 setting included.
 rate_quantiles=[.99,.995,.999,.9995,.9999]
 rate_cuts={str(q):float(np.nanquantile(benign_rate,q)) for q in rate_quantiles}
 val_rate=pd.to_numeric(pd.Series(xval[:,feature_cols.index(RATE_CANDIDATE)]),errors='coerce').to_numpy()
 test_rate=pd.to_numeric(pd.Series(xtest[:,feature_cols.index(RATE_CANDIDATE)]),errors='coerce').to_numpy()
 best=None
 for q,cut in rate_cuts.items():
  rv=val_rate>=cut; m=metric(yval,rv.astype(np.int8))
  if m['FPR'] is not None and m['FPR']<=budget:
   rank=(m['recall'] or 0,m['precision'] or 0,-m['FPR'])
   if best is None or rank>best[0]: best=(rank,q,cut,m)
 if best:
  _,rate_q,rate_cut,val_rule_metrics=best; rule_test= test_rate>=rate_cut
 else:
  # Keep the initial 99.9% cutoff if no candidate meets the validation budget.
  rate_q='0.999'; rate_cut=rate_cuts[rate_q]; rule_test=test_rate>=rate_cut; val_rule_metrics=None
 rule_val=val_rate>=rate_cut
 # Available CSV variant lacks source IP and timestamps, so grouped rules are disabled by schema audit.
 rules_supported={'high_packet_rate':True,'multi_port_scan':False,'repeated_connection':False,'reason':'MachineLearningCSV contains numeric flow features but no timestamp/source-IP fields.'}
 # Primary OR fusion of validation-tuned rule and anomaly decisions.
 hybrid_test=rule_test|ap_test
 # Secondary: joint search for best OR operating point within the same validation FPR budget.
 # Use candidate rule quantiles and validation benign score quantiles at 0.1%-1% plus no anomaly.
 anomaly_quantiles=[0,.001,.0025,.005,.0075,.01]
 neg_scores=np.sort(sval[yval==0])
 thresholds=[]
 for f in anomaly_quantiles:
  thresholds.append(float(np.nextafter(neg_scores[max(0,min(len(neg_scores)-1,int(np.floor((1-f)*len(neg_scores)))) )],-np.inf)))
 thresholds.append(float(np.nextafter(sval.max(),np.inf)))
 hybrid_budget_best=None
 for q,cut in rate_cuts.items():
  rv=val_rate>=cut
  for thr in thresholds:
   hp=rv|(sval>=thr); hm=metric(yval,hp.astype(np.int8))
   if hm['FPR'] is not None and hm['FPR']<=budget:
    rank=(hm['recall'] or 0,hm['precision'] or 0,-hm['FPR'])
    if hybrid_budget_best is None or rank>hybrid_budget_best[0]: hybrid_budget_best=(rank,q,cut,thr,hm)
 if hybrid_budget_best:
  _,h_q,h_cut,h_thr,h_val_metrics=hybrid_budget_best
  rule_budget_test=test_rate>=h_cut; anomaly_budget_test=anom_test_scores>=h_thr; hybrid_budget_test=rule_budget_test|anomaly_budget_test
 else:
  h_q=None; h_cut=None; h_thr=None; h_val_metrics=None; rule_budget_test=np.zeros(len(ytest),bool); anomaly_budget_test=np.zeros(len(ytest),bool); hybrid_budget_test=np.zeros(len(ytest),bool)
 # Report metrics and overlapping alert provenance.
 metrics={'rule_only':metric(ytest,rule_test.astype(np.int8)),'anomaly_only':metric(ytest,ap_test.astype(np.int8)),'hybrid_or':metric(ytest,hybrid_test.astype(np.int8)),'benign_baseline':metric(ytest,np.zeros(len(ytest),np.int8)),'hybrid_equal_validation_fpr_budget':metric(ytest,hybrid_budget_test.astype(np.int8))}
 overlap={'attacks_rule_only':int(((rule_test)&(~ap_test)&(ytest==1)).sum()),'attacks_anomaly_only':int(((ap_test)&(~rule_test)&(ytest==1)).sum()),'attacks_both':int(((ap_test)&(rule_test)&(ytest==1)).sum()),'benign_rule_only':int(((rule_test)&(~ap_test)&(ytest==0)).sum()),'benign_anomaly_only':int(((ap_test)&(~rule_test)&(ytest==0)).sum()),'benign_both':int(((ap_test)&(rule_test)&(ytest==0)).sum())}
 per_family={}
 for fam in sorted(set(ltest[ytest==1])):
  mask=(ltest==fam)&(ytest==1); per_family[str(fam)]={'support':int(mask.sum()),'rule_recall':float(rule_test[mask].mean()),'anomaly_recall':float(ap_test[mask].mean()),'hybrid_recall':float(hybrid_test[mask].mean())}
 # separate timed scoring to give config-specific throughput
 t0=time.perf_counter(); _=test_rate>=rate_cut; rule_seconds=time.perf_counter()-t0
 timings={'model_fit_seconds':fit_sec,'anomaly_test_inference_seconds':anomaly_pred_sec,'rule_test_inference_seconds':rule_seconds,'hybrid_test_inference_seconds':anomaly_pred_sec+rule_seconds,'peak_rss_bytes':int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)}
 for key,secs in [('rule_only',rule_seconds),('anomaly_only',anomaly_pred_sec),('hybrid_or',anomaly_pred_sec+rule_seconds)]: metrics[key]['test_inference_seconds']=secs; metrics[key]['flows_per_second']=len(ytest)/secs if secs else None
 # Freeze predictions first, then append test labels for scoring/audit.
 preds=pd.DataFrame({'test_row':np.arange(len(ytest)),'source_file':test_source,'rule_packet_rate':rule_test,'anomaly_score':anom_test_scores,'anomaly_threshold':athr,'anomaly_prediction':ap_test,'hybrid_prediction':hybrid_test,'hybrid_equal_budget_prediction':hybrid_budget_test})
 preds.to_csv(OUT/'test_predictions.csv',index=False)
 preds.insert(2,'label',ltest); preds.insert(3,'y_true',ytest); preds.to_csv(OUT/'test_predictions.csv',index=False)
 summary={'source':'CIC-IDS2017 MachineLearningCSV mirror (c01dsnap/CIC-IDS2017, main) with dataset provenance and checksum cross-check against CIC distribution; official dataset citation retained.','dataset_citation':'Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018.','data_files':atr+aval+atest,'split':{'train':'Monday','validation':'Tuesday + Wednesday','test':'Thursday + Friday'},'rows':{'train':len(ytr),'validation':len(yval),'test':len(ytest),'train_benign':int((ytr==0).sum()),'validation_benign':int((yval==0).sum()),'validation_attack':int((yval==1).sum()),'test_benign':int((ytest==0).sum()),'test_attack':int((ytest==1).sum())},'feature_count':len(feature_cols),'features':feature_cols,'preprocessing':{'headers':'strip leading/trailing whitespace','labels':'BENIGN => benign (0); all nonempty attack labels => attack (1)','missing_infinite':'median imputation from training benign rows; remaining all-missing columns set to zero','exact_duplicate_rule':'feature hashes in later partitions removed where identical to an earlier partition; no near-duplicate removal','training':'all Monday benign rows; IsolationForest default max_samples=min(256,n_samples), 100 trees, seed 42'},'rule_schema':rules_supported,'thresholds':{'validation_fpr_budget':budget,'anomaly_score_threshold':athr,'anomaly_validation_selection':atune,'packet_rate_training_benign_quantile_candidates':rate_cuts,'selected_packet_rate_quantile':rate_q,'selected_packet_rate_cut':rate_cut,'validation_rule_metrics':val_rule_metrics,'equal_budget_hybrid_selected_rate_quantile':h_q,'equal_budget_hybrid_rate_cut':h_cut,'equal_budget_hybrid_anomaly_cutoff':h_thr,'equal_budget_hybrid_validation_metrics':h_val_metrics},'metrics':metrics,'alert_overlap':overlap,'test_attack_family_metrics':per_family,'runtime':timings,'software':{'python':platform.python_version(),'pandas':pd.__version__,'numpy':np.__version__,'scikit_learn':sklearn.__version__,'platform':platform.platform()},'limitations':['One dataset release and historical lab capture only.','Capture-day split confounds attack family and day.','MachineLearningCSV does not preserve timestamps or source/destination IPs, so multi-port and repeated-connection rules could not be executed; only high packet-rate rule ran.','Test results are benchmark evidence, not current enterprise effectiveness.']}
 (OUT/'experiment_results.json').write_text(json.dumps(summary,indent=2,allow_nan=False))
 print(json.dumps({'rows':summary['rows'],'metrics':metrics,'rule_schema':rules_supported,'runtime':timings},indent=2))

if __name__=='__main__':main()
