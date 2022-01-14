1. Generate a new enviroment
     - in pycharm basically just make a new project its easier
     - in vsc or anything else: py -m venv myenv
         - in these others activate the env - myenv\Scripts\activate

3. to run either in terminal: ```flask run``` or in pycharmm click green play

4. check packages: ```pip list```

required base packages:
1. base flask - ```pip install flask```
2. marshmallow intergration - ```pip install flask-marshmallow```
3. marshmallow sqlalchemy intergration - ```pip install marshmallow-sqlalchemy```
4. sqlalchemy intergration - ```pip install flask-sqlalchemy ```


generating table requirements:
```python```
```from app import db```
```db.create_all()```
