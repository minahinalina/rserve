# forms.py
from flask_wtf import FlaskForm
from wtforms import SelectField, TimeField, StringField, SubmitField
from wtforms.validators import DataRequired

class Step1Form(FlaskForm):
    num_people = SelectField('人数', choices=[(str(i), str(i)) for i in range(1, 21)], validators=[DataRequired()])
    time = TimeField('時間', format='%H:%M', validators=[DataRequired()])
    location = StringField('現在地', validators=[DataRequired()])
    submit = SubmitField('空いている飲食店を探す')
