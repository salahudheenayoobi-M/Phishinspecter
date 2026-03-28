from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('fraud_detection', '0004_alter_upiid_options_alter_upiid_reported_count_and_more'),
    ]

    operations = [
        # Add new fields to UPIID
        migrations.AddField(
            model_name='upiid',
            name='scan_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='last_scan_ip',
            field=models.GenericIPAddressField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='upiid',
            name='is_blacklisted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='upiid',
            name='is_whitelisted',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='upiid',
            name='fraud_type',
            field=models.CharField(max_length=100, blank=True),
        ),
        migrations.AddField(
            model_name='upiid',
            name='threat_intel_hits',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='geo_risk_score',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='avg_txn_amount',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='max_txn_amount',
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='txn_velocity_24h',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='txn_velocity_1h',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='failed_txn_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='linked_fraud_count',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='upiid',
            name='risk_breakdown',
            field=models.JSONField(default=dict),
        ),
        # Create FraudReport table
        migrations.CreateModel(
            name='FraudReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fraud_type', models.CharField(
                    choices=[
                        ('phishing', 'Phishing'),
                        ('impersonation', 'Brand Impersonation'),
                        ('investment_scam', 'Investment Scam'),
                        ('lottery', 'Lottery / Prize Scam'),
                        ('job_scam', 'Job / Recruitment Scam'),
                        ('kyc_fraud', 'KYC / OTP Fraud'),
                        ('delivery_scam', 'Delivery Scam'),
                        ('other', 'Other'),
                    ],
                    default='other',
                    max_length=30,
                )),
                ('description', models.TextField(blank=True)),
                ('amount_lost', models.FloatField(blank=True, null=True)),
                ('reporter_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('reported_at', models.DateTimeField(auto_now_add=True)),
                ('upi', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='reports',
                    to='fraud_detection.upiid',
                )),
            ],
            options={'ordering': ['-reported_at']},
        ),
        # Create TransactionSignal table
        migrations.CreateModel(
            name='TransactionSignal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.FloatField()),
                ('success', models.BooleanField(default=True)),
                ('risk_flag', models.BooleanField(default=False)),
                ('signal_at', models.DateTimeField(auto_now_add=True)),
                ('upi', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='transaction_signals',
                    to='fraud_detection.upiid',
                )),
            ],
            options={'ordering': ['-signal_at']},
        ),
        migrations.AddIndex(
            model_name='transactionsignal',
            index=models.Index(fields=['upi', 'signal_at'], name='fraud_trans_upi_idx'),
        ),
    ]
