#!/usr/bin/env python

# ATT&CK Client Main Script - Drill-down capabilities at the tactic / technique / platform / data source levels
# Author: Jose Rodriguez (@Cyb3rPandaH)
# License: BSD 3-Clause
# Reference:
# https://github.com/Cyb3rWard0g/ATTACK-Python-Client
# https://stackoverflow.com/questions/27263805/pandas-when-cell-contents-are-lists-create-a-row-for-each-element-in-the-list/27266225?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
# https://stackoverflow.com/questions/19913659/pandas-conditional-creation-of-a-series-dataframe-column?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
# http://pandas.pydata.org/pandas-docs/version/0.22/generated/pandas.Series.str.contains.html
# https://chrisalbon.com/python/data_wrangling/pandas_dropping_column_and_rows/

from pandas import *
from pandas.io.json import json_normalize
from pandas import Series,DataFrame

from attackcti import attack_client

mitre = attack_client()

db = mitre.get_all_attack()
df = json_normalize(db)
df = df[[
    'matrix','tactic','technique','technique_id','technique_description',
    'mitigation','mitigation_description','group','group_id','group_aliases',
    'group_description','software','software_id','software_description','software_labels',
    'relationship_description','platform','data_sources','detectable_by_common_defenses','detectable_explanation',
    'difficulty_for_adversary','difficulty_explanation','effective_permissions','network_requirements','permissions_required',
    'remote_support','system_requirements','contributors','url']]

attributes = ['tactic','platform','data_sources']

for a in attributes:
    s = df.apply(lambda x: pandas.Series(x[a]),axis=1).stack().reset_index(level=1, drop=True)
    s.name = a + '_detail'
    df = df.drop(a, axis=1).join(s).reset_index(drop=True)

conditions = [(df['platform_detail']=='Linux')&(df['data_sources_detail'].str.contains('windows',case=False)== True),
             (df['platform_detail']=='macOS')&(df['data_sources_detail'].str.contains('windows',case=False)== True),
             (df['platform_detail']=='Linux')&(df['data_sources_detail'].str.contains('powershell',case=False)== True),
             (df['platform_detail']=='macOS')&(df['data_sources_detail'].str.contains('powershell',case=False)== True),
             (df['platform_detail']=='Linux')&(df['data_sources_detail'].str.contains('wmi',case=False)== True),
             (df['platform_detail']=='macOS')&(df['data_sources_detail'].str.contains('wmi',case=False)== True)]
choices = ['NO OK','NO OK','NO OK','NO OK','NO OK','NO OK']
df['Validation'] = np.select(conditions,choices,default='OK')

df_final = df[df.Validation == 'OK'].replace(['mitre-attack-mobile','Process monitoring'],['mitre-mobile-attack','Process Monitoring'])

df_final.to_csv('Mitre.csv',index=False,encoding='utf-8')