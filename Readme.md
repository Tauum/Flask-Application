1. Generate a new enviroment
     - in pycharm basically just make a new project its easier
     - in vsc or anything else: py -m venv myenv
         - in these others activate the env - myenv\Scripts\activate

3. to run either in terminal: ```flask run``` or in pycharmm click green play

4. check packages: ```pip list```

required base packages:
1. Base flask - ```pip install flask```
2. Marshmallow intergration - ```pip install flask-marshmallow```
3. Marshmallow sqlalchemy intergration - ```pip install marshmallow-sqlalchemy```
4. Sqlalchemy intergration - ```pip install flask-sqlalchemy ```


generating DB steps:
1. Open python client - ```python```
2. Import db - ```from app import db```
3. Generate tables - ```db.create_all()```
