# Postgres-Cell-Level-Security
Different Row Level Security (RLS) and Cell/Column Level Security Implementations For Postgres.

## Setup
Just run `setup.sql` on a fresh postgres instance. You'll get RLS all set up for a few tables, as well as some example queries.

## Reasoning
Quite often when you create a front end application, you just whip up a standard database (with password = "notsecurepleasechange") and off you go! Your app connects to the database as the default superuser (most often postgres), and you just have to be really careful to not leak the superuser credentials. You also have to be careful and not screw up any application logic, or you might give users access to all billing data, or even the ability to delete your entire database. Remember that time a guy deleted thousands of unsecured mongodb databases? [Scary stuff!](https://www.ehackingnews.com/2019/05/unistellar-attackers-delete-over-12000.html)

## The Premise
Instead of having your application control all database authorization (which gets exponentially harder the more people you add), move authorization to the database itself. This way you can hand out database access to just about anyone, including junior devs or even end users. Of course the setup will be different, but I think the trade-offs are worth it. This repository is a starting point for basic row and column security (cell level control) of your postgres database.

## How It Works
You're essentially creating auth tokens for each group that needs to access the database (managers, employees, users, etc.). You sign the auth token in a secure place (i.e. on your server) and can return that token to the user, or store it yourself in redis or even postgres. On each query, you set that token as a postgres config variable, which allows the end user to do what they need to do, and nothing else.

A very rough example is contained in `setup.sql`.  It creates tables (users, managers, employees, products), and defines who can do what. For example, a manager can see all other manager's ID's and usernames, but only their own salary.

![image](https://user-images.githubusercontent.com/2141012/115927663-00042300-a442-11eb-92e7-05b8c447a988.png)

There's also a view for managers to only see their own employees (`api.employees_v2`). If instead you wanted managers to see all employees, but only see and update their own employees' salaries you could set up it like the `api.managers` view.

Hopefully more examples and cleaner code (along with a basic sveltekit front end integration) are coming soon. PR's, suggestions and questions (whether or not I can answer them :) are welcome!

## Inspiration
I couldn't have made it without Bennie Swart's [awesome talk](https://www.youtube.com/watch?v=-9QqQ2jkG_4&t=2319s) and this [blog post](https://www.2ndquadrant.com/en/blog/application-users-vs-row-level-security/) by 2ndQuadrant.

