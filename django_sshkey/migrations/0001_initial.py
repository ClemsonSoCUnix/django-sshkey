# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserKey',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=50, blank=True)),
                ('key', models.TextField(max_length=2000)),
                ('fingerprint', models.CharField(db_index=True, max_length=47, blank=True)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_modified', models.DateTimeField(null=True)),
                ('last_used', models.DateTimeField(null=True)),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'sshkey_userkey',
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='userkey',
            unique_together=set([('user', 'name')]),
        ),
    ]
