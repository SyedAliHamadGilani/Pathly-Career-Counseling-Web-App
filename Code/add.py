from app import app, db, University

def add_demo_data():
    with app.app_context():
        # Check if data exists to avoid duplicates
        if University.query.count() > 0:
            print("Universities already exist in the database.")
            return

        universities = [
            University(
                name="University of Engineering and Technology (UET)",
                city="Lahore",
                website="https://uet.edu.pk",
                min_aggregate=60.0,
                is_approved=True
            ),
            University(
                name="FAST NUCES",
                city="Lahore",
                website="https://nu.edu.pk",
                min_aggregate=65.0,
                is_approved=True
            ),
            University(
                name="National University of Sciences and Technology (NUST)",
                city="Islamabad",
                website="https://nust.edu.pk",
                min_aggregate=75.0,
                is_approved=True
            ),
            University(
                name="Lahore University of Management Sciences (LUMS)",
                city="Lahore",
                website="https://lums.edu.pk",
                min_aggregate=85.0,
                is_approved=True
            ),
            University(
                name="NED University of Engineering & Technology",
                city="Karachi",
                website="https://neduet.edu.pk",
                min_aggregate=62.0,
                is_approved=True
            )
        ]

        db.session.bulk_save_objects(universities)
        db.session.commit()
        print("5 Demo Universities added successfully!")

if __name__ == "__main__":
    add_demo_data()