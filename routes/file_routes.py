
import io

from flask import (
    Blueprint, render_template, request,
    redirect, url_for, flash, send_file,
    abort, current_app
)

from flask_login import login_required, current_user

from database.db_manager import get_db
from services.file_service import (
    upload_file,
    download_file,
    delete_file
)
from services.audit_service import log_event

from services.file_service import verify_file_integrity

files = Blueprint("files", __name__)

@files.route("/files")
@login_required
def file_list():
    db = get_db()

    user_files = db.execute(
        """
        SELECT file_id, display_filename,
               encrypted_size, original_size,
               encryption_algorithm, created_at
        FROM files
        WHERE owner_id = ?
        ORDER BY created_at DESC
        """,
        (int(current_user.id),)
    ).fetchall()

    return render_template("files.html", files=user_files)

@files.route("/files/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file.", "error")
            return redirect(url_for("files.upload"))

        try:
            file_id = upload_file(
                uploaded_file,
                int(current_user.id)
            )

            flash(
                f"File encrypted successfully. ID: {file_id}",
                "success"
            )

            return redirect(url_for("files.file_list"))

        except ValueError as error:
            flash(str(error), "error")

        except Exception:
            current_app.logger.exception("File upload failed")
            flash("File upload failed. Please try again.", "error")

    return render_template("upload.html")

@files.route("/files/download/<int:file_id>")
@login_required
def download(file_id):
    try:
        result = download_file(file_id, int(current_user.id))

        if result is None:
            log_event(
                "UNAUTHORIZED_FILE_ACCESS",
                "DENIED",
                int(current_user.id),
                details="Attempted access to unavailable file"
            )
            abort(404)

        filename, decrypted_data = result

        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream"
        )

    except FileNotFoundError:
        flash("Encrypted file is missing.", "error")
        return redirect(url_for("files.file_list"))

    except Exception:
        current_app.logger.exception("File decryption failed")
        flash("Decryption failed. File may be corrupted.", "error")
        return redirect(url_for("files.file_list"))

@files.route("/files/delete/<int:file_id>", methods=["POST"])
@login_required
def remove(file_id):
    try:
        deleted = delete_file(file_id, int(current_user.id))

        if not deleted:
            log_event(
                "UNAUTHORIZED_FILE_DELETE",
                "DENIED",
                int(current_user.id),
                details="Attempted deletion of unavailable file"
            )
            return "File not found", 404

        flash("File deleted successfully.", "success")

    except FileNotFoundError:
        flash("Encrypted file is missing.", "error")

    except Exception:
        current_app.logger.exception("File deletion failed")
        flash("Unable to delete file.", "error")

    return redirect(url_for("files.file_list"))



@files.route("/files/verify/<int:file_id>", methods=["POST"])
@login_required
def verify_file(file_id):
    try:
        result = verify_file_integrity(file_id, current_user.id)
    except Exception:
        current_app.logger.exception("File integrity verification failed")
        flash(
            "Integrity verification failed. The file may be corrupted or missing.",
            "danger"
        )
        return redirect(url_for("files.file_list"))

    if result is None:
        abort(404)

    flash(
        "Integrity verified: file is authentic and unchanged.",
        "success"
    )
    return redirect(url_for("files.file_list"))
