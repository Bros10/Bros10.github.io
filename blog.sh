#!/bin/bash

###Script used to automate creating blog posts
###Usage bash blog.sh [Title] [Categorie1,Catergorie2] [Tag1,Tag2] 



dt=$(date '+%Y-%m-%d %H:%M:%S');

filename="$d-$1.md"

echo "$filename"

text="---
title: $1
author: Bros10
date: $dt +0000
categories: [Blogging, Tutorial]
tags: [writing]
---

Writeup coming soon
"

echo "$text"

echo "$text" > _posts/$filename 
bash run.sh

