package main

type Fundraise struct {
	Name          string
	Slug          string
	USCitizenOnly bool
	Link          string
}

var Fundraises = []Fundraise{
	{Name: "Biden/Harris", Slug: "biden-harris", USCitizenOnly: true, Link: "https://joebiden.com/"},
	{Name: "US Senate", Slug: "senate", USCitizenOnly: true, Link: "https://housework2020.org/senate-candidates"},
	{Name: "US House", Slug: "house", USCitizenOnly: true, Link: "https://housework2020.org/"},

	{Name: "RAICES", Slug: "raices", USCitizenOnly: false, Link: "https://www.raicestexas.org/"},
	{Name: "Democracy Docket", Slug: "democracy-docket", USCitizenOnly: false, Link: "https://www.democracydocket.com/"},
}

var FundraiseForSlug map[string]Fundraise

func init() {
	FundraiseForSlug = make(map[string]Fundraise)
	for _, f := range Fundraises {
		FundraiseForSlug[f.Slug] = f
	}
}

var csvheader = []string{
	0: "Receipt ID",
	"Date",
	"Amount",
	"Recurring Total Months",
	"Recurrence Number",
	"Recipient",
	"Fundraising Page",
	"Fundraising Partner",
	"Reference Code 2",
	"Reference Code",
	10: "Donor First Name",
	"Donor Last Name",
	"Donor Addr1",
	"Donor Addr2",
	"Donor City",
	"Donor State",
	"Donor ZIP",
	"Donor Country",
	"Donor Occupation",
	"Donor Employer",
	20: "Donor Email",
	"Donor Phone",
	"New Express Signup",
	"Comments",
	"Check Number",
	"Check Date",
	"Employer Addr1",
	"Employer Addr2",
	"Employer City",
	"Employer State",
	30: "Employer ZIP",
	"Employer Country",
	"Donor ID",
	"Fundraiser ID",
	"Fundraiser Recipient ID",
	"Fundraiser Contact Email",
	"Fundraiser Contact First Name",
	"Fundraiser Contact Last Name",
	"Partner ID",
	"Partner Contact Email",
	40: "Partner Contact First Name",
	"Partner Contact Last Name",
	"Reserved",
	"Lineitem ID",
	"AB Test Name",
	"AB Variation",
	"Recipient Committee",
	"Recipient ID",
	"Recipient Gov ID",
	"Recipient Election",
	50: "Reserved",
	"Payment ID",
	"Payment Date",
	"Disbursement ID",
	"Disbursement Date",
	"Recovery ID",
	"Recovery Date",
	"Refund ID",
	"Refund Date",
	"Fee",
	"Recur Weekly",
	"ActBlue Express Lane",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Mobile",
	"Recurring Upsell Shown",
	"Recurring Upsell Succeeded",
	"Double Down",
	"Smart Recurring",
	"Monthly Recurring Amount",
	"Apple Pay",
	"Card Replaced by Account Updater",
	"ActBlue Express Donor",
	"Custom Field 1 Label",
	"Custom Field 1 Value",
	"Donor US Passport Number",
	"Text Message Opt In",
	"Gift Identifier",
	"Gift Declined",
	"Shipping Addr1",
	"Shipping City",
	"Shipping State",
	"Shipping Zip",
	"Shipping Country",
	"Weekly Recurring Amount",
	"Smart Boost Amount",
	"Smart Boost Shown",
}
