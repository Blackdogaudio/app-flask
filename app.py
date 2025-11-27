from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime

###############################################################################
# App setup
###############################################################################
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')

# -----------------------------
# Jinja helpers for templates
# -----------------------------
from urllib.parse import urlparse

ADMIN_USERS = 'mark'

@app.template_test('image_url')
def is_image_url(url: str) -> bool:
    """Return True if the URL looks like a direct image link by extension."""
    if not url or not isinstance(url, str):
        return False
    lower = url.split('?', 1)[0].lower()
    exts = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg')
    return lower.endswith(exts)


@app.template_filter('domain')
def extract_domain(url: str) -> str:
    """Extract host from a URL for favicon usage. Falls back to the raw string."""
    try:
        netloc = urlparse(url).netloc
        return netloc or url
    except Exception:
        return url


@app.template_filter('date_only')
def jinja_date_only(value):
    """Render only the date (YYYY-MM-DD) from an ISO8601 datetime string or datetime.

    Safely handles values like '2025-11-26T14:10:32Z' or naive ISO strings.
    If parsing fails, falls back to the first 10 characters or the original string.
    """
    if not value:
        return ''
    try:
        if isinstance(value, str):
            s = value
            # Support trailing 'Z' by converting to +00:00 for fromisoformat
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            dt = datetime.fromisoformat(s)
        elif isinstance(value, datetime):
            dt = value
        else:
            return str(value)
        return dt.date().isoformat()
    except Exception:
        try:
            return str(value)[:10]
        except Exception:
            return str(value)

###############################################################################
# Very simple JSON storage using ./db.json
# We keep existing keys (like entries, meta) and add our own:
# - users: list of {username, password_hash, created_at}
# - wishlists: {username: [
#       {
#         list_id, name, slug, is_public, created_at,
#         items: [ {id, title, description, url, priority, purchased, added_at} ]
#       }
#   ]}
# Migration: older format was wishlists[username] = [ items... ]. We wrap those
# into a single list named "My Wishlist" with slug "default".
###############################################################################
DB_PATH = os.path.join(os.path.dirname(__file__), 'db.json')



def _load_db():
    if not os.path.exists(DB_PATH):
        data = {"users": [], "wishlists": {}, "meta": {"next_id": 1, "next_list_id": 1}}
        with open(DB_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return data
    with open(DB_PATH, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            return {"users": [], "wishlists": {}, "meta": {"next_id": 1, "next_list_id": 1}}
        data = json.loads(content)
        # Initialize missing structures without disturbing existing data
        data.setdefault('users', [])
        data.setdefault('wishlists', {})
        data.setdefault('meta', {})
        data['meta'].setdefault('next_id', 1)
        data['meta'].setdefault('next_list_id', 1)

        # Migration from old schema: wishlists[username] was a list of items
        # Detect if the first element looks like an item (has 'id' and no 'items')
        migrated = False
        for username, val in list(data['wishlists'].items()):
            if isinstance(val, list):
                if len(val) == 0:
                    # Ensure it's a list of wishlist objects in new format
                    data['wishlists'][username] = []
                else:
                    first = val[0]
                    if isinstance(first, dict) and 'id' in first and 'items' not in first:
                        # Wrap into a single wishlist
                        list_id = data['meta']['next_list_id']
                        data['meta']['next_list_id'] += 1
                        new_list = {
                            'list_id': list_id,
                            'name': 'My Wishlist',
                            'slug': 'default',
                            'is_public': False,
                            'created_at': datetime.utcnow().isoformat() + 'Z',
                            'items': val
                        }
                        data['wishlists'][username] = [new_list]
                        migrated = True
                    elif all(isinstance(x, dict) and 'items' in x for x in val):
                        # Already new format
                        pass
                    else:
                        # Unknown; normalize to empty
                        data['wishlists'][username] = []
        # Ensure each item has a link_type field (default 'item')
        mutated = migrated
        for uname, lists in data['wishlists'].items():
            for lst in lists if isinstance(lists, list) else []:
                items = lst.get('items', [])
                for it in items:
                    if isinstance(it, dict) and 'link_type' not in it:
                        it['link_type'] = 'item'
                        mutated = True
        if mutated:
            # Persist migration and normalization right away
            _save_db(data)
        return data


def _save_db(data):
    with open(DB_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def get_user(username):
    db = _load_db()
    return next((u for u in db['users'] if u['username'].lower() == username.lower()), None)


def create_user(username, password):
    username = username.strip()
    if not username or not password:
        return False, 'Username and password are required.'
    db = _load_db()
    if any(u['username'].lower() == username.lower() for u in db['users']):
        return False, 'Username already exists.'
    hashed = generate_password_hash(password)
    db['users'].append({
        'username': username,
        'password_hash': hashed,
        'created_at': datetime.utcnow().isoformat() + 'Z'
    })
    # Create a default list for new user
    db['wishlists'].setdefault(username, [])
    list_id = db['meta'].get('next_list_id', 1)
    db['meta']['next_list_id'] = list_id + 1
    default_list = {
        'list_id': list_id,
        'name': 'My Wishlist',
        'slug': 'default' if not any(l.get('slug') == 'default' for l in db['wishlists'][username]) else f"list-{list_id}",
        'is_public': False,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'items': []
    }
    db['wishlists'][username].append(default_list)
    _save_db(db)
    return True, None


def verify_user(username, password):
    user = get_user(username)
    if not user:
        return False
    return check_password_hash(user['password_hash'], password)


def login_required(owner_check=False):
    def decorator(fn):
        from functools import wraps

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to continue.', 'warning')
                return redirect(url_for('login', next=request.path))
            if owner_check:
                username = kwargs.get('username')
                if username and session.get('username') != username:
                    abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# -----------------------------
# Admin helpers
# -----------------------------
def is_admin(username: str) -> bool:
    """Return True if the given username is allowed to access admin pages.

    Admin user list can be configured via env var ADMIN_USERS as a comma-separated
    list of usernames. The username 'admin' is always considered an admin.
    """
    if not username:
        return False
    if username.lower() == 'admin':
        return True
    if username.lower() == 'mark':
        return True
    env_val = os.getenv('ADMIN_USERS', '')
    if not env_val:
        return False
    allowed = {u.strip().lower() for u in env_val.split(',') if u.strip()}
    return username.lower() in allowed


def admin_required(fn):
    """Decorator to require login and admin status."""
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login', next=request.path))
        if not is_admin(session.get('username')):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


@app.context_processor
def inject_helpers():
    """Expose helper(s) to templates."""
    return {
        'is_admin': is_admin,
    }

###############################################################################
# Helpers for wishlist operations
###############################################################################

def _slugify(name: str) -> str:
    import re
    s = name.strip().lower()
    s = re.sub(r'[^a-z0-9\-\s]', '', s)
    s = re.sub(r'\s+', '-', s).strip('-')
    return s or 'list'


def _get_user_lists(db, username: str):
    return db['wishlists'].setdefault(username, [])


def _find_list(db, username: str, slug: str):
    lists = _get_user_lists(db, username)
    return next((lst for lst in lists if lst.get('slug') == slug), None)


def _ensure_list_slug_unique(db, username: str, base_slug: str) -> str:
    slug = base_slug
    lists = _get_user_lists(db, username)
    existing = {l.get('slug') for l in lists}
    if slug not in existing:
        return slug
    i = 2
    while True:
        candidate = f"{base_slug}-{i}"
        if candidate not in existing:
            return candidate
        i += 1


###############################################################################
# Routes
###############################################################################
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('user_lists', username=session['username']))
    return render_template('index.html', title='Wishlist')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ok, err = create_user(username, password)
        if ok:
            session['username'] = username
            flash('Welcome! Your account has been created.', 'success')
            return redirect(url_for('user_lists', username=username))
        else:
            flash(err, 'error')
    return render_template('register.html', title='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if verify_user(username, password):
            session['username'] = username
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('user_lists', username=username))
        flash('Invalid username or password.', 'error')
    return render_template('login.html', title='Login')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/u/<username>')
def user_lists(username):
    db = _load_db()
    is_owner = session.get('username') == username
    lists = _get_user_lists(db, username)
    visible_lists = lists if is_owner else [l for l in lists if l.get('is_public')]
    return render_template('user_lists.html',
                           title=f"{username}'s Wishlists",
                           username=username,
                           lists=visible_lists,
                           is_owner=is_owner)


@app.route('/u/<username>/<slug>')
def user_wishlist(username, slug):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    is_owner = session.get('username') == username
    if not is_owner and not lst.get('is_public'):
        abort(404)
    # Sorting: visitors see purchased items fall to the bottom; owners do not sort by purchased
    if is_owner:
        items = sorted(lst.get('items', []), key=lambda x: (x.get('priority', 999)))
    else:
        items = sorted(lst.get('items', []), key=lambda x: (x.get('purchased', False), x.get('priority', 999)))
    return render_template('wishlist.html',
                           title=f"{username} · {lst.get('name')}",
                           username=username,
                           list_name=lst.get('name'),
                           slug=lst.get('slug'),
                           is_public=lst.get('is_public'),
                           items=items,
                           is_owner=is_owner)


@app.post('/u/<username>/<slug>/add')
@login_required(owner_check=True)
def add_item(username, slug):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    url_field = request.form.get('url', '').strip()
    priority = request.form.get('priority', '3').strip()
    link_type = request.form.get('link_type', 'item').strip().lower()
    if link_type not in {'item', 'wishlist'}:
        link_type = 'item'
    try:
        priority = int(priority)
    except ValueError:
        priority = 3
    if not title:
        flash('Title is required.', 'error')
        return redirect(url_for('user_wishlist', username=username, slug=slug))
    item_id = db['meta'].get('next_id', 1)
    db['meta']['next_id'] = item_id + 1
    item = {
        'id': item_id,
        'title': title,
        'description': description,
        'url': url_field,
        'priority': max(1, min(priority, 5)),
        'purchased': False,
        'added_at': datetime.utcnow().isoformat() + 'Z',
        'link_type': link_type
    }
    lst.setdefault('items', []).append(item)
    _save_db(db)
    flash('Item added to your wishlist.', 'success')
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/<slug>/toggle/<int:item_id>')
@login_required(owner_check=True)
def toggle_item(username, slug, item_id):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    for it in lst.get('items', []):
        if it.get('id') == item_id:
            it['purchased'] = not it.get('purchased', False)
            break
    _save_db(db)
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/<slug>/delete/<int:item_id>')
@login_required(owner_check=True)
def delete_item(username, slug, item_id):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    items = lst.get('items', [])
    lst['items'] = [it for it in items if it.get('id') != item_id]
    _save_db(db)
    flash('Item removed.', 'info')
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/<slug>/public_toggle/<int:item_id>')
def public_toggle(username, slug, item_id):
    """Allow non-owners to mark an item purchased on public lists.
    Owners cannot use this endpoint, and private lists are not accessible.
    """
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    # Only for public lists
    if not lst.get('is_public'):
        abort(404)
    # Owners are not allowed to see/modify purchased via this endpoint
    if session.get('username') == username:
        abort(403)
    purchased_val = request.form.get('purchased', 'off')
    for it in lst.get('items', []):
        if it.get('id') == item_id:
            it['purchased'] = True if purchased_val == 'on' else False
            break
    _save_db(db)
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.route('/u/<username>/<slug>/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required(owner_check=True)
def edit_item(username, slug, item_id):
    """Edit an existing wishlist item (owner only)."""
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    items = lst.get('items', [])
    item = next((it for it in items if it.get('id') == item_id), None)
    if not item:
        abort(404)

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        url_field = request.form.get('url', '').strip()
        priority = request.form.get('priority', str(item.get('priority', 3))).strip()
        link_type = request.form.get('link_type', item.get('link_type', 'item')).strip().lower()
        purchased_val = request.form.get('purchased', 'off')

        if link_type not in {'item', 'wishlist'}:
            link_type = 'item'
        try:
            priority = int(priority)
        except ValueError:
            priority = item.get('priority', 3)

        if not title:
            flash('Title is required.', 'error')
            return redirect(url_for('edit_item', username=username, slug=slug, item_id=item_id))

        # Apply updates
        item['title'] = title
        item['description'] = description
        item['url'] = url_field
        item['priority'] = max(1, min(priority, 5))
        item['link_type'] = link_type
        item['purchased'] = True if purchased_val == 'on' else False

        _save_db(db)
        flash('Item updated.', 'success')
        return redirect(url_for('user_wishlist', username=username, slug=slug))

    # GET
    is_owner = session.get('username') == username
    return render_template('edit_item.html',
                           title=f"Edit · {item.get('title')}",
                           username=username,
                           slug=slug,
                           item=item,
                           is_owner=is_owner)


@app.post('/u/<username>/lists/create')
@login_required(owner_check=True)
def create_list(username):
    db = _load_db()
    name = request.form.get('name', '').strip() or 'New List'
    base_slug = _slugify(name)
    slug = _ensure_list_slug_unique(db, username, base_slug)
    list_id = db['meta'].get('next_list_id', 1)
    db['meta']['next_list_id'] = list_id + 1
    new_list = {
        'list_id': list_id,
        'name': name,
        'slug': slug,
        'is_public': False,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'items': []
    }
    _get_user_lists(db, username).append(new_list)
    _save_db(db)
    flash('List created.', 'success')
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/lists/<slug>/rename')
@login_required(owner_check=True)
def rename_list(username, slug):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    new_name = request.form.get('name', '').strip()
    if not new_name:
        flash('Name is required.', 'error')
        return redirect(url_for('user_wishlist', username=username, slug=slug))
    lst['name'] = new_name
    # Keep slug unless user changed name to something that collides and slug was 'list-...' optional to change; keep stable
    _save_db(db)
    flash('List renamed.', 'success')
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/lists/<slug>/visibility')
@login_required(owner_check=True)
def set_visibility(username, slug):
    db = _load_db()
    lst = _find_list(db, username, slug)
    if not lst:
        abort(404)
    vis = request.form.get('is_public', 'off')
    lst['is_public'] = True if vis == 'on' else False
    _save_db(db)
    flash('Visibility updated.', 'success')
    return redirect(url_for('user_wishlist', username=username, slug=slug))


@app.post('/u/<username>/lists/<slug>/delete')
@login_required(owner_check=True)
def delete_list(username, slug):
    db = _load_db()
    lists = _get_user_lists(db, username)
    if len(lists) <= 1:
        flash('You cannot delete your last list.', 'error')
        return redirect(url_for('user_lists', username=username))
    before = len(lists)
    lists[:] = [l for l in lists if l.get('slug') != slug]
    _save_db(db)
    if len(lists) < before:
        flash('List deleted.', 'info')
    return redirect(url_for('user_lists', username=username))


@app.route('/browse')
@login_required()
def browse():
    db = _load_db()
    public_lists = []
    for uname, lists in db.get('wishlists', {}).items():
        for lst in lists:
            if lst.get('is_public'):
                public_lists.append({
                    'username': uname,
                    'name': lst.get('name'),
                    'slug': lst.get('slug'),
                    'count': len(lst.get('items', [])),
                    'created_at': lst.get('created_at')
                })
    # Sort by created_at or name
    public_lists.sort(key=lambda x: (x.get('username'), x.get('name').lower()))
    return render_template('browse.html', title='Browse Public Wishlists', lists=public_lists)


###############################################################################
# Admin: DB editor & download
###############################################################################
@app.get('/admin/db')
@admin_required
def admin_db_view():
    """Show an admin-only page to view and edit the JSON database file."""
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = json.dumps({"users": [], "wishlists": {}, "meta": {"next_id": 1, "next_list_id": 1}}, indent=2)
    return render_template('admin_db.html', title='Admin · DB Editor', content=content)


@app.post('/admin/db')
@admin_required
def admin_db_save():
    """Validate and save edited JSON, pretty-printed, atomically."""
    raw = request.form.get('content', '')
    if not raw:
        flash('No content provided.', 'error')
        return redirect(url_for('admin_db_view'))
    try:
        data = json.loads(raw)
    except Exception as e:
        flash(f'Invalid JSON: {e}', 'error')
        return redirect(url_for('admin_db_view'))

    # Write atomically: write to temp file, then replace
    dir_name = os.path.dirname(DB_PATH)
    tmp_path = os.path.join(dir_name, f'.db.json.tmp')
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        os.replace(tmp_path, DB_PATH)
        flash('Database saved successfully.', 'success')
    except Exception as e:
        # Clean up tmp on failure
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        flash(f'Failed to save database: {e}', 'error')
    return redirect(url_for('admin_db_view'))


@app.get('/admin/db/download')
@admin_required
def admin_db_download():
    """Send the current db.json as a download."""
    # Ensure the file exists
    _load_db()
    return send_file(DB_PATH, as_attachment=True, download_name='db.json', mimetype='application/json')

###############################################################################
# Entrypoint
###############################################################################
if __name__ == '__main__':
    # For local dev convenience
    # app.run(debug=True)
# run on all interfaces, port 80
    app.run(host='0.0.0.0', port=80)