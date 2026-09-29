import json
from database.connection import create_connection


def save_scan(
    input_type,
    input_text,
    url,
    email,
    score,
    risk_level,
    findings
):
    connection = create_connection()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO scans
            (
                input_type,
                input_text,
                url,
                email,
                risk_score,
                risk_level,
                findings
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        values = (
            input_type,
            input_text,
            url,
            email,
            score,
            risk_level,
            json.dumps(findings)
        )

        cursor.execute(query, values)
        connection.commit()

        return True

    except Exception as error:
        connection.rollback()
        print(f"Error saving scan: {error}")
        return False

    finally:
        if cursor:
            cursor.close()

        connection.close()