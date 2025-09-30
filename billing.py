import stripe
import streamlit as st
import os
from datetime import datetime, timedelta
from database import get_db_connection
import json

# Stripe configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Pricing plans
PRICING_PLANS = {
    "free": {
        "name": "Free Tier",
        "price": 0,
        "scans_per_month": 5,
        "features": [
            "5 scans per month",
            "Basic vulnerability scanning",
            "CVE database access",
            "Community support"
        ],
        "stripe_price_id": None
    },
    "pro": {
        "name": "Professional",
        "price": 29.99,
        "scans_per_month": 999999,  # Unlimited
        "features": [
            "Unlimited scans",
            "Advanced vulnerability assessment",
            "Shodan integration",
            "PDF report generation",
            "AI-powered analysis",
            "Priority support",
            "Compliance mapping"
        ],
        "stripe_price_id": os.getenv("STRIPE_PRO_PRICE_ID", "")
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 99.99,
        "scans_per_month": 999999,  # Unlimited
        "features": [
            "Everything in Professional",
            "White-label reports",
            "API access",
            "Custom integrations",
            "Dedicated support",
            "SLA guarantee",
            "Team management"
        ],
        "stripe_price_id": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "")
    }
}

def create_stripe_customer(user_info):
    """Create a Stripe customer"""
    if not STRIPE_SECRET_KEY:
        raise Exception("Stripe not configured")
    
    try:
        customer = stripe.Customer.create(
            email=user_info['email'],
            name=user_info['username'],
            metadata={
                'user_id': user_info['id'],
                'username': user_info['username']
            }
        )
        
        # Update user record with Stripe customer ID
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users SET stripe_customer_id = ? WHERE id = ?
        """, (customer.id, user_info['id']))
        
        conn.commit()
        conn.close()
        
        return customer.id
        
    except stripe.error.StripeError as e:
        raise Exception(f"Stripe error: {str(e)}")

def get_or_create_customer(user_info):
    """Get existing Stripe customer or create new one"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT stripe_customer_id FROM users WHERE id = ?", (user_info['id'],))
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0]:
        return result[0]
    else:
        return create_stripe_customer(user_info)

def create_checkout_session(user_info, plan_id):
    """Create Stripe checkout session"""
    if not STRIPE_SECRET_KEY:
        raise Exception("Stripe not configured")
    
    if plan_id not in PRICING_PLANS or plan_id == "free":
        raise Exception("Invalid plan selected")
    
    plan = PRICING_PLANS[plan_id]
    customer_id = get_or_create_customer(user_info)
    
    try:
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': plan['stripe_price_id'],
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{os.getenv('BASE_URL', 'http://localhost:5000')}/billing?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{os.getenv('BASE_URL', 'http://localhost:5000')}/billing?canceled=true",
            metadata={
                'user_id': user_info['id'],
                'plan': plan_id
            }
        )
        
        return session.url
        
    except stripe.error.StripeError as e:
        raise Exception(f"Checkout session creation failed: {str(e)}")

def get_customer_subscriptions(customer_id):
    """Get customer's active subscriptions"""
    if not STRIPE_SECRET_KEY:
        return []
    
    try:
        subscriptions = stripe.Subscription.list(
            customer=customer_id,
            status='active'
        )
        return subscriptions.data
        
    except stripe.error.StripeError:
        return []

def cancel_subscription(subscription_id):
    """Cancel a subscription"""
    if not STRIPE_SECRET_KEY:
        raise Exception("Stripe not configured")
    
    try:
        subscription = stripe.Subscription.delete(subscription_id)
        return subscription
        
    except stripe.error.StripeError as e:
        raise Exception(f"Subscription cancellation failed: {str(e)}")

def update_user_subscription_status(user_id, plan, subscription_id=None):
    """Update user's subscription status in database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE users 
        SET role = ?, subscription_id = ?, subscription_updated_at = ?
        WHERE id = ?
    """, (plan, subscription_id, datetime.now(), user_id))
    
    conn.commit()
    conn.close()

def get_usage_statistics(user_id):
    """Get user's current usage statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get current month usage
    cursor.execute("""
        SELECT COUNT(*) FROM scan_results 
        WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    """, (user_id,))
    
    monthly_scans = cursor.fetchone()[0]
    
    # Get total usage
    cursor.execute("SELECT COUNT(*) FROM scan_results WHERE user_id = ?", (user_id,))
    total_scans = cursor.fetchone()[0]
    
    # Get reports generated
    cursor.execute("SELECT COUNT(*) FROM reports WHERE user_id = ?", (user_id,))
    total_reports = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'monthly_scans': monthly_scans,
        'total_scans': total_scans,
        'total_reports': total_reports
    }

def render_billing_interface():
    """Render billing and subscription interface"""
    st.title("💳 Billing & Subscription Management")
    
    user_info = st.session_state.get('user_info', {})
    if not user_info:
        st.error("Please log in to access billing")
        return
    
    # Current subscription info
    current_plan = user_info.get('role', 'free')
    
    st.markdown("### 📊 Current Subscription")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Current Plan", PRICING_PLANS[current_plan]['name'])
    
    with col2:
        st.metric("Monthly Price", f"${PRICING_PLANS[current_plan]['price']}")
    
    with col3:
        st.metric("Monthly Scans", 
                 "Unlimited" if PRICING_PLANS[current_plan]['scans_per_month'] > 1000 
                 else str(PRICING_PLANS[current_plan]['scans_per_month']))
    
    # Usage statistics
    usage_stats = get_usage_statistics(user_info['id'])
    
    st.markdown("### 📈 Usage Statistics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("This Month's Scans", usage_stats['monthly_scans'])
    
    with col2:
        st.metric("Total Scans", usage_stats['total_scans'])
    
    with col3:
        st.metric("Reports Generated", usage_stats['total_reports'])
    
    # Pricing plans
    st.markdown("### 💰 Available Plans")
    
    # Plan comparison
    plan_cols = st.columns(len(PRICING_PLANS))
    
    for i, (plan_id, plan_info) in enumerate(PRICING_PLANS.items()):
        with plan_cols[i]:
            # Plan card
            is_current = current_plan == plan_id
            
            if is_current:
                st.success(f"✅ **{plan_info['name']}** (Current)")
            else:
                st.markdown(f"**{plan_info['name']}**")
            
            st.markdown(f"### ${plan_info['price']}/month")
            
            st.markdown("**Features:**")
            for feature in plan_info['features']:
                st.markdown(f"• {feature}")
            
            if not is_current and plan_id != 'free':
                if st.button(f"Upgrade to {plan_info['name']}", key=f"upgrade_{plan_id}"):
                    try:
                        checkout_url = create_checkout_session(user_info, plan_id)
                        st.markdown(f"[Complete Purchase]({checkout_url})")
                        st.success("Click the link above to complete your subscription")
                    except Exception as e:
                        st.error(f"Error creating checkout session: {str(e)}")
            
            if is_current and plan_id != 'free':
                if st.button("Cancel Subscription", key=f"cancel_{plan_id}"):
                    st.warning("Are you sure you want to cancel your subscription?")
                    if st.button("Yes, Cancel", key=f"confirm_cancel_{plan_id}"):
                        # In a real implementation, this would cancel via Stripe
                        st.success("Subscription canceled (demo)")
    
    # Billing history
    st.markdown("### 📄 Billing History")
    
    if STRIPE_SECRET_KEY and user_info.get('stripe_customer_id'):
        try:
            customer_id = user_info['stripe_customer_id']
            
            # Get invoices
            invoices = stripe.Invoice.list(customer=customer_id, limit=10)
            
            if invoices.data:
                invoice_data = []
                for invoice in invoices.data:
                    invoice_data.append([
                        datetime.fromtimestamp(invoice.created).strftime('%Y-%m-%d'),
                        f"${invoice.amount_paid / 100:.2f}",
                        invoice.status.title(),
                        invoice.hosted_invoice_url or "N/A"
                    ])
                
                st.table({
                    'Date': [row[0] for row in invoice_data],
                    'Amount': [row[1] for row in invoice_data],
                    'Status': [row[2] for row in invoice_data],
                    'Invoice': [row[3] for row in invoice_data]
                })
            else:
                st.info("No billing history available")
                
        except Exception as e:
            st.error(f"Error loading billing history: {str(e)}")
    else:
        st.info("Connect Stripe to view billing history")
    
    # Payment methods
    st.markdown("### 💳 Payment Methods")
    
    if STRIPE_SECRET_KEY:
        st.info("Payment methods are managed through Stripe's secure portal")
        if st.button("Manage Payment Methods"):
            st.info("This would redirect to Stripe's customer portal")
    else:
        st.warning("⚠️ Stripe integration not configured. Payment processing is unavailable.")
        st.markdown("""
        **To enable billing:**
        1. Set up a Stripe account at [stripe.com](https://stripe.com)
        2. Configure environment variables:
           - `STRIPE_SECRET_KEY`
           - `STRIPE_PUBLISHABLE_KEY`
           - `STRIPE_PRO_PRICE_ID`
           - `STRIPE_ENTERPRISE_PRICE_ID`
        3. Set up webhook endpoints for subscription events
        """)

def handle_stripe_webhook(payload, sig_header):
    """Handle Stripe webhook events"""
    if not STRIPE_SECRET_KEY:
        return False
    
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        
        # Handle subscription events
        if event['type'] == 'customer.subscription.created':
            subscription = event['data']['object']
            customer_id = subscription['customer']
            
            # Get user by customer ID
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,))
            user = cursor.fetchone()
            
            if user:
                # Update subscription status
                plan = 'pro'  # Determine plan from subscription
                update_user_subscription_status(user[0], plan, subscription['id'])
            
            conn.close()
            
        elif event['type'] == 'customer.subscription.deleted':
            subscription = event['data']['object']
            customer_id = subscription['customer']
            
            # Downgrade user to free plan
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (customer_id,))
            user = cursor.fetchone()
            
            if user:
                update_user_subscription_status(user[0], 'free', None)
            
            conn.close()
        
        return True
        
    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return False

def check_subscription_limits(user_info):
    """Check if user has exceeded subscription limits"""
    current_plan = user_info.get('role', 'free')
    plan_limits = PRICING_PLANS[current_plan]
    
    usage_stats = get_usage_statistics(user_info['id'])
    monthly_scans = usage_stats['monthly_scans']
    
    if monthly_scans >= plan_limits['scans_per_month']:
        return False, f"Monthly scan limit reached ({plan_limits['scans_per_month']})"
    
    return True, f"{monthly_scans}/{plan_limits['scans_per_month']} scans used"

def get_billing_analytics():
    """Get billing analytics for admin dashboard"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Count users by plan
    cursor.execute("""
        SELECT role, COUNT(*) 
        FROM users 
        GROUP BY role
    """)
    
    plan_counts = dict(cursor.fetchall())
    
    # Revenue calculation (simplified)
    monthly_revenue = (
        plan_counts.get('pro', 0) * PRICING_PLANS['pro']['price'] +
        plan_counts.get('enterprise', 0) * PRICING_PLANS['enterprise']['price']
    )
    
    conn.close()
    
    return {
        'total_users': sum(plan_counts.values()),
        'free_users': plan_counts.get('free', 0),
        'pro_users': plan_counts.get('pro', 0),
        'enterprise_users': plan_counts.get('enterprise', 0),
        'monthly_revenue': monthly_revenue
    }
