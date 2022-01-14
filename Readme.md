1. Generate a new enviroment
     - in pycharm basically just make a new project its easier
     - in vsc or anything else: py -m venv myenv
         - in these others activate the env - myenv\Scripts\activate

2. generate a new primary app file 

3. to run either in terminal: ```flask run``` or in pycharmm click green play

4. check packages: ```pip list```

required base packages:
```pip install flask```
```pip install flask-marshmallow```
```pip install marshmallow-sqlalchemy```
```pip install flask-sqlalchemy ```


generating table requirements:
```python```
```from app import db```
```db.create_all()```
