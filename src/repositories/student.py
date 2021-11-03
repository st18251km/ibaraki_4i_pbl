from main import db
from main import Student


def read_by_id(student_name):
    student = db.session.query(Student).filter_by(name=student_name).first()
    print(student)
    return student