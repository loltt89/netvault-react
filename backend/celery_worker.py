#!/usr/bin/env python3
"""
Celery Worker for NetVault Django
"""
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netvault.settings')

# Import Django and setup
import django
django.setup()

# Import Celery app
from netvault.celery import app as celery

# This will auto-discover tasks from all installed apps
celery.autodiscover_tasks()
