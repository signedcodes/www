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
