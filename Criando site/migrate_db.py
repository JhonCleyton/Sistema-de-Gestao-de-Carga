from app import db, app

with app.app_context():
    # Drop existing tables
    db.drop_all()

    # Create new tables with updated schema
    db.create_all()

    print("Database schema updated successfully!")
