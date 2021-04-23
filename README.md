# Postgres-Cell-Level-Security
Different Row Level Security (RLS) and Cell/Column Level Security Implementations For Postgres.

## Reasoning
Quite often when you create a front end application, you just whip up a standard database (with password = "notsecurepleasechange") and off you go! Your app connects to the database as the default superuser (most often postgres), and you just have to be really careful to not leak the superuser credentials. You also have to be careful and not screw up any applicaiton logic, or you might give users access to all billing data, or even the ability to delete your entire database. Remember that time a guy deleted thousands of unsecured mongodb databases? [Scary stuff!](https://www.ehackingnews.com/2019/05/unistellar-attackers-delete-over-12000.html)

## The Premise
Instead of having your application control all database authorization (which gets exponentially harder the more people you add), move authorization to the database itself. This way you can hand out database access to just about anyone, including junior devs or even end users. Of course the setup will be different, but I think the trade-offs are worth it. This repository is a starting point for basic row and column security (cell level control) of your postgres database.

## How It Works
You're essentially creating auth tokens for each group that needs to access the database (managers, employees, users, etc.). You sign the auth token in a secure place (i.e. on your server) and can return that token to the user, or store it yourself in redis or even postgres. On each query, you set that token as a postgres config variable, which allows the end user to do what they need to do, and nothing else.

A very rough example is contained in `seed.sql`.
