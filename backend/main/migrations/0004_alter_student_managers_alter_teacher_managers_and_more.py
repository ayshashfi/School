# Generated by Django 5.0.7 on 2024-07-15 17:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("main", "0003_alter_student_managers_alter_teacher_managers_and_more"),
    ]

    operations = [
        migrations.AlterModelManagers(name="student", managers=[],),
        migrations.AlterModelManagers(name="teacher", managers=[],),
        migrations.AlterModelManagers(name="user", managers=[],),
    ]
