# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_sshkey', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userkey',
            name='fingerprint',
            field=models.CharField(db_index=True, max_length=128, blank=True),
        ),
    ]
