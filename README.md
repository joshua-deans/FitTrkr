# fitTrkr
This is a Fitness and Workout Tracking app called fitTrkr using [Flask](https://github.com/pallets/flask) Backend with MySQL from Scratch. 

=====

### Requirements
..* Python
..* pip
..* MySQL

###Setting up the Project
Fork the repository and cd into to Project Directory
1. pip install flask
2. pip install flask_mysqldb
3. pip install wtforms
4. pip install passlib
5. pip install functools
6. Set up the Database

### Run the Project
`cd FitnessTracker`

`python app.py`

`Point yor browser to [Localhost](https://localhost:5000)`


##### Setting up Database, make sure that database is set up
`CREATE DATABASE fitTrkr;`

#### USE myflaskapp db using MySQL
`USE fitTrkr;`

```
CREATE TABLE MealPlan
	(
	MealPlanID    	INT(11) AUTO_INCREMENT,
	MealPlanName 	VARCHAR(30),
	Category    	VARCHAR(50),
	DietaryRestrictions	 VARCHAR(200),
	MealPlanDescription	 VARCHAR(500),
	Primary Key(MealPlanID)
	);
```

```
CREATE TABLE Meals
	(
	MealID INT(11) AUTO_INCREMENT,
	MealType	VARCHAR(30),
	MealName	VARCHAR(50),
	CaloriesPerServing	INT,
	DietaryRestrictions	VARCHAR(300),
	MealDescription    	VARCHAR(500),
	Primary Key(MealID)
	);
```

```
CREATE TABLE WorkoutPlan
	(
	WorkoutPlanID INT(11) AUTO_INCREMENT,
	WorkoutPlanName VARCHAR(30),
	Intensity    	VARCHAR(30),
	PlanDescription	VARCHAR(500),
	Primary Key (WorkoutPlanID)
	);
```

```
CREATE TABLE Workouts
	(
	WorkoutID INT(11) AUTO_INCREMENT,
	Intensity VARCHAR(30),
	WorkoutDescription VARCHAR(500),
	Equipment VARCHAR(300),
	WorkoutName VARCHAR(140),
	Primary Key (WorkoutID)
	);
```

```
CREATE TABLE Cardio
	(
	WorkoutID INT(11) AUTO_INCREMENT,
	Distance VARCHAR(30),
	Duration VARCHAR(30),
	CardioType VARCHAR(30),
	Primary Key (WorkoutID),
	Foreign Key(WorkoutID) references Workouts(WorkoutID)
	ON DELETE CASCADE
	ON UPDATE CASCADE
	);
```

```
CREATE TABLE Strength
	(
	WorkoutID INT(11) AUTO_INCREMENT,
	BodyPart VARCHAR(50),
	StrengthType VARCHAR(30),
	Primary Key (WorkoutID),
	Foreign Key (WorkoutID) references Workouts(WorkoutID)
	    ON DELETE CASCADE
	    ON UPDATE CASCADE
	);
```

```
CREATE TABLE MealPlan_Meal
	(
	MealPlanID INT(11) AUTO_INCREMENT,
	MealPlanName VARCHAR(50),
	MealID INT(11),
	MealTime CHAR(50),
	Primary Key(MealplanID, MealID),
	Foreign Key(MealplanID) references MealPlan(MealplanID)
		ON DELETE NO ACTION
		ON UPDATE CASCADE,
	Foreign Key(MealID) references Meals(MealID)
		ON DELETE NO ACTION	
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE Workout_Comprise_WPlan
	(
	WorkoutPlanID INT(11),
	WorkoutPlanName VARCHAR(50),
	WorkOutID INT(11),
	NumSets INT(11),
	NumReps INT(11),
	Primary Key(WorkoutPlanID, WorkOutID),
	Foreign Key(WorkoutPlanID) references WorkoutPlan(WorkoutPlanID)
		ON DELETE NO ACTION
        ON UPDATE CASCADE,
	Foreign Key(WorkOutID) references Workouts(WorkOutID)
		ON DELETE NO ACTION
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE PostalCode
(
	PostalCode VARCHAR(6),
	City VARCHAR(100),
	ProvinceState VARCHAR(30),
	Country VARCHAR(100),
	Primary Key(PostalCode)
);
```

```
CREATE TABLE Users
(
	UserID INT(11) AUTO_INCREMENT,
	UserName VARCHAR(30) UNIQUE,
	FirstName VARCHAR(30),
	LastName VARCHAR(30),
	PasswordHash CHAR(64),
	PasswordSalt CHAR(32),
	Gender VARCHAR(10),
	Age INT(11),
	Address VARCHAR(100),
	PostalCode VARCHAR(6),
	Primary Key (UserID),
	Foreign Key(PostalCode) references PostalCode(PostalCode)
		ON DELETE NO ACTION 
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE Session
(
	UserID INT(11) AUTO_INCREMENT,
	Token CHAR(128),
	Primary Key (UserID, Token),
	Foreign Key(UserID) references Users(UserID)
		ON DELETE CASCADE
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE Clients
(
	UserID INT(11) AUTO_INCREMENT,
	Height DOUBLE,
	Weight DOUBLE,
	PrimaryGoals VARCHAR(300),
	FitnessLevel VARCHAR(140),
	Primary Key(UserID),
	Foreign Key(UserID) references Users(UserID)
		ON DELETE CASCADE
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE Trainers
(
	UserID INT(11),
	TrainerFocus VARCHAR(300),
	Primary Key (UserID),
	Foreign Key(UserID) references Users(UserID)
		ON DELETE CASCADE
		ON UPDATE CASCADE
	);
```

```
CREATE TABLE FitnessProgram
	(
	FitnessProgramID INT(11) AUTO_INCREMENT,
	FitnessProgramName VARCHAR(30);
	FP_intensity VARCHAR(50),
	Description VARCHAR(400),
	Program_Length VARCHAR(20),
	TrainerID INT(11),
	WorkoutPlanID INT NOT NULL,
	MealPlanID INT NOT NULL,
	Primary Key (FitnessProgramID),
	Foreign Key (TrainerID) references Trainer(UserID)
		ON DELETE SET NULL
		ON UPDATE CASCADE,
	Foreign Key(WorkoutPlanID) references WorkoutPlan(WorkoutPlanID)
		ON DELETE NO ACTION
		ON UPDATE CASCADE,
	Foreign Key(MealPlanID) references MealPlan(MealPlanID)
		ON DELETE NO ACTION
        ON UPDATE CASCADE
	);
```

```
CREATE TABLE Logs
	(
	UserID INT(11) AUTO_INCREMENT,
	LogID INT(11),
	FitnessProgramID INT NOT NULL,
	LogDate DATE,
	Weight DOUBLE,
	WorkoutCompletion INT(11),
	Notes VARCHAR(1000),
	SatisfactionLevel INT(11),
	MealCompletion INT(11),
	Primary Key(UserID, logID),
	Foreign Key(UserID) references Users(UserID)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
	Foreign Key(FitnessProgramID) references FitnessProgram(FitnessProgramID)
		ON DELETE NO ACTION
		ON UPDATE NO ACTION
	);
```

```
CREATE TABLE Preq_Fitness
	(
	PrereqProgramID INT(11) AUTO_Increment,
	FitnessProgramID INT(11),
	Primary key (PrereqProgramID, FitnessProgramID),
	Foreign key(PrereqProgramID) references FitnessProgram(FitnessProgramID)
		ON DELETE NO ACTION
		ON UPDATE NO ACTION,
	Foreign key(FitnessProgramID) references FitnessProgram(FitnessProgramID)
		ON DELETE NO ACTION
		ON UPDATE NO ACTION
	);
```


Set Up db.py as follows:
```
def DBconfig():
    dbconfig = {
        "host": 'localhost', 
        "user": 'root',
        "password": 'fitness2018!',
        "DBName": 'fitTrkr',
        "dictDB": 'DictCursor',
    }
    return dbconfig
```

