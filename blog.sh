#!/bin/bash

###Script used to automate creating blog posts
###Usage bash blog.sh Title 

dt=$(date '+%d-%m-%Y %H:%M:%S');
d=$(date '+%d-%m-%Y');

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

#touch /_posts/$filename
echo "$text" > _posts/$filename 
###printf "$text" "$1" "$dt" 

###OUTPUT=$(printf "$text" "$1" "$dt" 2>&1)

###echo "$OUTPUT" > /_posts/
