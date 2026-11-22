"""Deterministic bounded isolation trees adapted from the project's previous AD.

No legacy database or per-session training loop is imported.
"""
import math
import random

def _expected_path(n):
    if n<=1:return 0.
    if n==2:return 1.
    return 2*(math.log(n-1)+0.5772156649015329)-2*(n-1)/n


class SmallIsolationForest:
    """Bounded reference isolation-tree implementation, deterministic and serializable."""
    def __init__(self,trees=32,sample=128,seed=17):self.count=trees;self.sample=sample;self.seed=seed;self.trees=[]
    def fit(self,rows):
        rng=random.Random(self.seed);size=min(self.sample,len(rows));depth=math.ceil(math.log2(max(2,size)))
        def grow(values,level):
            if len(values)<=1 or level>=depth:return {'n':len(values)}
            features=[i for i in range(len(values[0])) if min(row[i] for row in values)<max(row[i] for row in values)]
            if not features:return {'n':len(values)}
            feature=rng.choice(features);lo=min(row[feature] for row in values);hi=max(row[feature] for row in values)
            split=rng.uniform(lo,hi);left=[row for row in values if row[feature]<split];right=[row for row in values if row[feature]>=split]
            if not left or not right:return {'n':len(values)}
            return {'f':feature,'v':split,'l':grow(left,level+1),'r':grow(right,level+1)}
        self.size=size;self.trees=[grow(rng.sample(rows,size),0) for _ in range(self.count)];return self
    def score(self,row):
        def length(node,level):
            if 'n' in node:return level+_expected_path(node['n'])
            return length(node['l'] if row[node['f']]<node['v'] else node['r'],level+1)
        denominator=_expected_path(self.size)
        return 2**(-(sum(length(tree,0) for tree in self.trees)/len(self.trees))/denominator) if denominator else .5


