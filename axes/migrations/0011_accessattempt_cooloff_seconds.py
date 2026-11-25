# Generated for progressive lockout tier windows
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("axes", "0010_accessattemptexpiration"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessattempt",
            name="cooloff_seconds",
            field=models.PositiveIntegerField(
                blank=True,
                db_index=True,
                help_text=(
                    "Cool-off window that applies to this attempt, resolved "
                    "from the lockout tier matched when the attempt was "
                    "recorded. Null means a permanent attempt that does not "
                    "expire automatically."
                ),
                null=True,
                verbose_name="Cool-off Seconds",
            ),
        ),
    ]
